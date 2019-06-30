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
#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
#include "cryptopp/sha.h"
using CryptoPP::SHA256;
#include "cryptopp/filters.h"
using CryptoPP::Redirector;
using CryptoPP::StringSink;
using CryptoPP::StringSource;

#include "google/protobuf/util/json_util.h"
#include "protos_pb_h/transaction.pb.h"
#include "protos_pb_h/batch.pb.h"

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

std::string hashData(std::string data)
{
    /////////////////////////////////////////////
    //Create a SHA-512 data Hash
    std::vector<uint8_t> message_vect(data.begin(), data.end());
    std::string digest_hex;
    HexEncoder encoder(new StringSink(digest_hex), false);
    std::string digest;

    SHA256 hash;
    hash.Update(message_vect.data(), message_vect.size());
    digest.resize(hash.DigestSize());
    hash.Final((byte *)&digest[0]);
    StringSource ss(digest, true, new Redirector(encoder));
    return digest_hex;
}

static SECP256K1_API::secp256k1_context *ctx = SECP256K1_API::secp256k1_context_create(SECP256K1_CONTEXT_SIGN);

int main(int argc, char **argv)
{
    json payload;
    payload["Verb"] = "set";
    payload["Name"] = "foo";
    payload["Value"] = 42;

    std::vector<uint8_t> payload_vect = json::to_cbor(payload);
    std::string payload_str(payload_vect.begin(), payload_vect.end());

    std::string message = payload_str; //"test";
    std::string message_hash;
    const unsigned char *message_hash_char;

    unsigned char privateKey[PRIVATE_KEY_SIZE];
    std::string privateKey_str;
    size_t publicKey_serilized_len = (size_t)PUBLIC_KEY_SERILIZED_SIZE;
    unsigned char publicKey_serilized[PUBLIC_KEY_SERILIZED_SIZE];
    SECP256K1_API::secp256k1_pubkey publicKey;
    std::string publicKey_str;

    SECP256K1_API::secp256k1_ecdsa_signature signature;
    std::string signature_str;

    /* Generate a random key */
    {
        generatePrivateKey(privateKey, PRIVATE_KEY_SIZE);
        while (SECP256K1_API::secp256k1_ec_seckey_verify(ctx, privateKey) == 0) //regenerate private key until it is valid
        {
            generatePrivateKey(privateKey, PRIVATE_KEY_SIZE);
        }
        CHECK(SECP256K1_API::secp256k1_ec_seckey_verify(ctx, privateKey) == 1);
        privateKey_str = hexStr(privateKey, PRIVATE_KEY_SIZE);
        std::cout << "Private key verified.\n->Using:" << privateKey_str << std::endl;
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
        CHECK(SECP256K1_API::secp256k1_ec_pubkey_serialize(ctx, publicKey_serilized, &publicKey_serilized_len, &publicKey, SECP256K1_EC_COMPRESSED) == 1);
        publicKey_str = hexStr(publicKey_serilized, PUBLIC_KEY_SERILIZED_SIZE);
        std::cout << "Public key serilized ok." << std::endl;
        std::cout << "->Using:" << publicKey_str << std::endl;
        //probably will need to prepend "0" to the pubkey above: because the compressed version of this pub key should ALLWAYS start by "02" or "03".
    }

    /* Hash message */
    {
        std::cout << "Message test is ok." << std::endl;
        std::cout << "->Using:" << message << std::endl;
        message_hash = hashData(message);
        message_hash_char = (const unsigned char *)message_hash.c_str();
        std::cout << "SHA256 test is ok." << std::endl;
        std::cout << "->Using:" << message_hash << std::endl;
    }

    /* Signing */
    {
        CHECK(SECP256K1_API::secp256k1_ecdsa_sign(ctx, &signature, message_hash_char, privateKey, NULL, NULL) == 1);
        signature_str = hexStr(signature.data, 32);
        std::cout << "Signing test is ok." << std::endl;
        std::cout << "->Using:" << signature_str << std::endl;
    }

    std::cout << "***Start build real transaaction***" << std::endl;

    //PROTOBUF
    //init Batch
    BatchList myBatchList;                      //init batch list
    Batch *myBatch = myBatchList.add_batches(); //init the one batch that will be sent
    BatchHeader myBatchHeader;                  //init batch header
    //init Transaction
    TransactionList transaction_list;                                 //init transaction list
    Transaction *myTransaction = transaction_list.add_transactions(); //init the one transaction that will be sent
    TransactionHeader myTransactionHeader;                            //init transaction header

    //tool to convert into json and print the transaction proto:
    google::protobuf::util::JsonPrintOptions json_options;
    json_options.add_whitespace = true;
    json_options.always_print_primitive_fields = true;
    json_options.always_print_enums_as_ints = true;
    json_options.preserve_proto_field_names = true;

    //first build transaction
    //& add all necessary data to protos messages
    myTransactionHeader.Clear();
    myTransactionHeader.set_batcher_public_key(publicKey_str);                                                //set batcher pubkey
    myTransactionHeader.set_signer_public_key(publicKey_str);                                                 //set signer pubkey
    myTransactionHeader.set_family_name("intkey");                                                            //the transaction familly to use
    myTransactionHeader.set_family_version("1.0");                                                            //familly version
    myTransactionHeader.set_payload_sha512(message_hash);                                                     //set a hash sha512 of the payload
    myTransactionHeader.add_inputs("1cf1266e282c41be5e4254d8820772c5518a2c5a8c0c7f7eda19594a7eb539453e1ed7"); //1cf126cc488cca4cc3565a876f6040f8b73a7b92475be1d0b1bc453f6140fba7183b9a
    myTransactionHeader.add_outputs("1cf1266e282c41be5e4254d8820772c5518a2c5a8c0c7f7eda19594a7eb539453e1ed7");
    //done transaction header
    myTransaction->Clear();
    myTransaction->set_payload(payload_vect.data(), payload_vect.size());
    myTransaction->set_header(myTransactionHeader.SerializePartialAsString());               //build a string of the transaction header
    std::string myTransactionHeader_string = myTransactionHeader.SerializePartialAsString(); //serialize batch header to string

    message_hash = hashData(myTransactionHeader_string);
    message_hash_char = (const unsigned char *)message_hash.c_str();
    CHECK(SECP256K1_API::secp256k1_ecdsa_sign(ctx, &signature, message_hash_char, privateKey, NULL, NULL) == 1); //make signature
    signature_str = hexStr(signature.data, 32);
    myTransaction->set_header_signature(signature_str); //set header signature

    //done transaction

    //add transaction to batch header
    myBatchHeader.add_transaction_ids(signature_str); //add transaction to batch

    //build batch
    myBatchHeader.set_signer_public_key(publicKey_str); //set batch public key
    //myBatchHeader.SerializeToOstream()
    std::string myBatchHeader_string = myBatchHeader.SerializePartialAsString(); //serialize batch header to string
    myBatch->set_header(myBatchHeader_string);                                   //set header

    message_hash = hashData(myBatchHeader_string);
    message_hash_char = (const unsigned char *)message_hash.c_str();
    CHECK(SECP256K1_API::secp256k1_ecdsa_sign(ctx, &signature, message_hash_char, privateKey, NULL, NULL) == 1); //make signature
    signature_str = hexStr(signature.data, 32);

    myBatch->set_header_signature(signature_str);

    std::cout << "***Done build real transaaction***" << std::endl;

    myBatchList.SerializePartialToOstream(&std::cout);

    return 0;
}
