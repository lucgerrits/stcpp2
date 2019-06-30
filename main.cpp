/*
Build test transaction (for Sawtooth Hyperledger)
This will later on:
- build pub/priv keys
- make (random) payload
- sign/build transaction based on keys and payload
- send the batch transaction to sawtooth already existing network
*/
#include <iostream>
#include <fstream>
#include <iomanip>
#include <stdio.h>
#include "base64/base64.h"
#include <curl/curl.h>
#include <assert.h>
#include <string>
#include <sys/stat.h>
#include "nlohmann/json.hpp"
using json = nlohmann::json;

typedef unsigned char byte;

#define PRIVATEKEY_FILENAME "ec.private.key"
#define PUBLICKEY_FILENAME "ec.public.key"
#define SAWTOOTH_REST_API "https://sawtooth-explore-8090.gerrits-luc.com"
#define SAWTOOTH_BATCH_MAX_TRANSACTIONS 100
#define PRIVATE_KEY_SIZE 32
#define PUBLIC_KEY_SIZE 64
#define PUBLIC_KEY_SERILIZED_SIZE 33

void abort(void) __THROW __attribute__((__noreturn__));
#define TEST_FAILURE(msg)                                        \
    do                                                           \
    {                                                            \
        fprintf(stderr, "%s:%d: %s\n", __FILE__, __LINE__, msg); \
        abort();                                                 \
    } while (0)
#define EXPECT(x, c) __builtin_expect((x), (c))
#define CHECK(cond)                                        \
    do                                                     \
    {                                                      \
        if (EXPECT(!(cond), 0))                            \
        {                                                  \
            TEST_FAILURE("test condition failed: " #cond); \
        }                                                  \
    } while (0)

// #include "secp256k1/include/secp256k1_ecdh.h"
#include "secp256k1/include/secp256k1.h"
// #include "secp256k1/include/secp256k1_preallocated.h"

#include "cryptopp/cryptlib.h"
#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;

//https://stackoverflow.com/a/14051107/11697589
std::string hexStr(byte *data, int len) //bytes to string
{
    std::stringstream ss;
    ss << std::hex;
    for (int i(0); i < len; ++i)
        ss << (int)data[i];
    return ss.str();
}
//http://www.cplusplus.com/forum/general/53397/
int chhex(char ch)
{
    if (isdigit(ch))
        return ch - '0';
    if (tolower(ch) >= 'a' && tolower(ch) <= 'f')
        return ch - 'a' + 10;
    return -1;
}
void hexstrToUchar(unsigned char *dest, const char *source, int bytes_n)
{
    for (bytes_n--; bytes_n >= 0; bytes_n--)
        dest[bytes_n] = 16 * chhex(source[bytes_n * 2]) + chhex(source[bytes_n * 2 + 1]);
}
void generatePrivateKey(byte *key, int length)
{
    AutoSeededRandomPool rng;
    rng.GenerateBlock(key, length);
    std::cout << "generatePrivateKey:" << hexStr(key, length) << std::endl;
}

static SECP256K1_API::secp256k1_context *ctx = SECP256K1_API::secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

int main(int argc, char **argv)
{
    json payload;
    payload["Verb"] = "set";
    payload["Name"] = "foo";
    payload["Value"] = 42;

    unsigned char privateKey[PRIVATE_KEY_SIZE];
    size_t publicKey_serilized_len = (size_t)PUBLIC_KEY_SERILIZED_SIZE;
    unsigned char publicKey_serilized[PUBLIC_KEY_SERILIZED_SIZE];
    SECP256K1_API::secp256k1_pubkey publicKey;
    // secp256k1_ecdsa_signature signature;

    /* Generate a random key */
    {
        generatePrivateKey(privateKey, PRIVATE_KEY_SIZE);
        while (SECP256K1_API::secp256k1_ec_seckey_verify(ctx, privateKey) == 0) //regenerate private key until it is valid
        {
            generatePrivateKey(privateKey, PRIVATE_KEY_SIZE);
        }
        CHECK(SECP256K1_API::secp256k1_ec_seckey_verify(ctx, privateKey) == 1);
        std::cout << "Private key verified.\n->Using:" << hexStr(privateKey, PRIVATE_KEY_SIZE) << std::endl;
    }

    /* Generate a public key */
    {
        //FAILING:Segmentation fault
        CHECK(SECP256K1_API::secp256k1_ec_pubkey_create(ctx, &publicKey, privateKey) == 1);
        std::cout << "Public key verified." << std::endl;
        std::cout << "->Using:" << hexStr(publicKey.data, PUBLIC_KEY_SIZE) << std::endl;
    }

    /* Serilize public key */
    {
        SECP256K1_API::secp256k1_ec_pubkey_serialize(ctx, publicKey_serilized, &publicKey_serilized_len, &publicKey, SECP256K1_EC_COMPRESSED);
        std::cout << "Public key serilized ok." << std::endl;        
        std::cout << "->Using:" << hexStr(publicKey_serilized, PUBLIC_KEY_SERILIZED_SIZE) << std::endl;
        //probably will need to prepend "0" to the pubkey above: because the compressed version of this pub key should ALLWAYS start by "02" or "03".
    }

    return 0;
}
