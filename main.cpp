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

#include "secp256k1/include/secp256k1_ecdh.h"
#include "secp256k1/include/secp256k1.h"
#include "secp256k1/include/secp256k1_preallocated.h"
using SECP256K1_API::secp256k1_ec_pubkey_create;

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
}

int main(int argc, char **argv)
{
    json payload;
    payload["Verb"] = "set";
    payload["Name"] = "foo";
    payload["Value"] = 42;

    secp256k1_context *ctx;
    secp256k1_pubkey publicKey;
    unsigned char privateKey[PRIVATE_KEY_SIZE];
    // secp256k1_ecdsa_signature signature;

    std::ifstream privateKey_file;
    privateKey_file.open(PRIVATEKEY_FILENAME);
    if (privateKey_file.is_open())
    {
        std::string line;
        std::getline(privateKey_file, line);
        privateKey_file.close();
        if (line.length() == (int)PRIVATE_KEY_SIZE * 2)
        {
            /* Retrieve the key */
            hexstrToUchar(privateKey, line.c_str(), PRIVATE_KEY_SIZE);
            CHECK(secp256k1_ec_seckey_verify(ctx, privateKey) == 1);
            std::cout << "Existing key ok:" << hexStr(privateKey, PRIVATE_KEY_SIZE) << std::endl;
        }
        else
        {
            /* Generate a random key */
            while (hexStr(privateKey, PRIVATE_KEY_SIZE).length() != (int)PRIVATE_KEY_SIZE * 2)
            {
                generatePrivateKey(privateKey, PRIVATE_KEY_SIZE);
            }
            CHECK(secp256k1_ec_seckey_verify(ctx, privateKey) == 1);
            std::cout << "New key ok:" << hexStr(privateKey, PRIVATE_KEY_SIZE) << std::endl;
            std::ofstream privateKey_file;
            privateKey_file.open(PRIVATEKEY_FILENAME);
            privateKey_file << hexStr(privateKey, PRIVATE_KEY_SIZE);
            privateKey_file.close();
        }
    }
    else
    {
        std::cout << "Unable to open " << PRIVATEKEY_FILENAME << std::endl;
        /* Generate a random key */
        while (hexStr(privateKey, PRIVATE_KEY_SIZE).length() != (int)PRIVATE_KEY_SIZE * 2)
        {
            generatePrivateKey(privateKey, PRIVATE_KEY_SIZE);
        }
        CHECK(secp256k1_ec_seckey_verify(ctx, privateKey) == 1);
        std::cout << "New key ok:" << hexStr(privateKey, PRIVATE_KEY_SIZE) << std::endl;
        std::ofstream privateKey_file;
        privateKey_file.open(PRIVATEKEY_FILENAME);
        privateKey_file << hexStr(privateKey, PRIVATE_KEY_SIZE);
        privateKey_file.close();
    }

    /* Generate a public key */
    {
        //FAILING:Segmentation fault
        CHECK(secp256k1_ec_pubkey_create(ctx, &publicKey, privateKey) == 1);
    }
    return 0;
}
