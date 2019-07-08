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

#include "cxxopts/include/cxxopts.hpp" //to parse arguments

#include "nlohmann/json.hpp"
using json = nlohmann::json;

//typedef unsigned char byte; //is missing for some case

//////////////////////////////////////////////////////////////////
//Define some constants:
// #define PRIVATEKEY_FILENAME "ec.private.key"
// #define PUBLICKEY_FILENAME "ec.public.key"
// #define SAWTOOTH_REST_API "https://sawtooth-explore-8090.gerrits-luc.com"
// #define SAWTOOTH_BATCH_MAX_TRANSACTIONS 100
#define PRIVATE_KEY_SIZE 32
#define PUBLIC_KEY_SIZE 64
#define PUBLIC_KEY_SERILIZED_SIZE 33
#define PRIVATE_KEY "0152fdf6e81e0a694cf8f361e14d32d8b25e605c669dc06940c500c546ee8a3f"
#define PUBLIC_KEY "0265e1a0353a5de3ad229f0c96fe4851949c856d5ad57717d4615c981ddea1f841"
#define SIGNATURE_SERILIZED_SIZE 64
#define HASH_SHA256_SIZE 32

//////////////////////////////////////////////////////////////////
//To show errors:
/*void abort(void) __THROW __attribute__((__noreturn__));
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
    } while (0)*/
//////////////////////////////////////////////////////////////////
//secp256k1
#include "secp256k1/include/secp256k1.h"
// #include "secp256k1/include/secp256k1_ecdh.h"
// #include "secp256k1/include/secp256k1_preallocated.h"
//////////////////////////////////////////////////////////////////
//crypto++
#include "cryptopp/cryptlib.h"
#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;
#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
#include "cryptopp/sha.h"
using CryptoPP::SHA256;
using CryptoPP::SHA512;
#include "cryptopp/filters.h"
using CryptoPP::Redirector;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
//////////////////////////////////////////////////////////////////
//protobuf
#include "protobuf/.libs/include/google/protobuf/util/json_util.h"
#include "protos_pb_h/transaction.pb.h"
#include "protos_pb_h/batch.pb.h"
//////////////////////////////////////////////////////////////////
//END TOP MAIN

//////////////////////////////////////////////////////////////////
//global variables:
static SECP256K1_API::secp256k1_context *ctx = SECP256K1_API::secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
std::string mode = "normal";
std::string intkey_cmd = "set";
std::string intkey_key = "foo";
int intkey_value = 42;
int i;
std::string batch_api_endpoint = "";

//////////////////////////////////////////////////////////////////
//Functions:

//following the example: https://github.com/jarro2783/cxxopts/blob/master/src/example.cpp
cxxopts::ParseResult
parse(int argc, char *argv[])
{
    try
    {
        cxxopts::Options options(argv[0], " - example command line options");
        options
            .positional_help("[optional args]")
            .show_positional_help();

        options
            .allow_unrecognised_options()
            .add_options()("t,test", "Test the program")
            ("url", "Sawtooth REST API endpoint", cxxopts::value<std::string>())
            ("c,cmd", "Inkey CMD: set, dec or inc", cxxopts::value<std::string>())
            //Inkey key
            ("k,key", "Inkey key: set, dec or inc", cxxopts::value<std::string>())
            //Inkey value
            ("v,value", "Inkey value: set, dec or inc", cxxopts::value<int>());

        auto result = options.parse(argc, argv);

        if (result.count("t"))
        {
            //go for test mode
            mode = "test";
        }
        if (result.count("cmd"))
        {
            //go for test mode
            intkey_cmd = result["cmd"].as<std::string>();
        }
        if (result.count("key"))
        {
            //go for test mode
            intkey_key = result["key"].as<std::string>();
        }
        if (result.count("value"))
        {
            //go for test mode
            intkey_value = result["value"].as<int>();
        }
        if(result.count("url"))
        {
            batch_api_endpoint = result["url"].as<std::string>();//"http://10.212.104.144:8021/batches"
        }

        return result;
    }
    catch (const cxxopts::OptionException &e)
    {
        std::cout << "error parsing options: " << e.what() << std::endl;
        exit(1);
    }
}

//https://stackoverflow.com/a/14051107/11697589
//https://stackoverflow.com/questions/7639656/getting-a-buffer-into-a-stringstream-in-hex-representation/7639754#7639754
std::string UcharToHexStr(unsigned char *data, int len) //bytes to string
{
    //this was first:
    // std::stringstream ss;
    // for (int i = 0; i < data_length; ++i)
    //     ss << std::hex << (int)data[i];
    // std::string mystr = ss.str();

    //the following is better: IT FILLS WITH 0 !!!!
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (int i = 0; i < len; ++i)
        ss << std::setw(2) << static_cast<unsigned>(data[i]);
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
void HexStrToUchar(unsigned char *dest, const char *source, int bytes_n)
{
    for (bytes_n--; bytes_n >= 0; bytes_n--)
        dest[bytes_n] = 16 * chhex(source[bytes_n * 2]) + chhex(source[bytes_n * 2 + 1]);
}
void generateRandomBytes(unsigned char *key, int length)
{
    AutoSeededRandomPool rng;
    rng.GenerateBlock(key, length);
}

std::string sha256Data(std::string data)
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
    hash.Final((unsigned char *)&digest[0]);
    StringSource ss(digest, true, new Redirector(encoder));
    return digest_hex;
}

std::string sha512Data(std::string data)
{
    /////////////////////////////////////////////
    //Create a SHA-512 data Hash
    std::vector<uint8_t> message_vect(data.begin(), data.end());
    std::string digest_hex;
    HexEncoder encoder(new StringSink(digest_hex), false);
    std::string digest;

    SHA512 hash;
    hash.Update(message_vect.data(), message_vect.size());
    digest.resize(hash.DigestSize());
    hash.Final((unsigned char *)&digest[0]);
    StringSource ss(digest, true, new Redirector(encoder));
    return digest_hex;
}

void emptyBytes(unsigned char *data, int len)
{
    for (int i(0); i < len; ++i)
        data[i] = 0x00;
}
std::string ToHex(std::string s, bool upper_case = false)
{
    std::ostringstream ret;

    for (std::string::size_type i = 0; i < s.length(); ++i)
        ret << std::hex << std::setfill('0') << std::setw(2) << (upper_case ? std::uppercase : std::nouppercase) << (int)s[i];

    return ret.str();
}
void buildAddress(std::string txnFamily, std::string entryName, unsigned char *ouput35bytes)
{
    //this address is used for intkey transaction processor
    // Example: txnFamily="intkey", entryName="name"
    //Doc: https://sawtooth.hyperledger.org/docs/core/releases/latest/app_developers_guide/address_and_namespace.html#address-components
    emptyBytes(ouput35bytes, 35);
    std::string txnFamily_hex_str = sha512Data(txnFamily);
    unsigned char txnFamily_hex_char[6];
    HexStrToUchar(txnFamily_hex_char, txnFamily_hex_str.c_str(), 6);
    for (int i = 0; i < (6 / 2); i++)
    {
        ouput35bytes[i] = txnFamily_hex_char[i];
    }
    std::string entryName_hex_str = sha512Data(entryName);
    entryName_hex_str = entryName_hex_str.substr(entryName_hex_str.size() - 64, entryName_hex_str.size());
    unsigned char entryName_hex_char[64];
    HexStrToUchar(entryName_hex_char, entryName_hex_str.c_str(), 64);
    for (int i = 0; i < (64 / 2); i++)
    {
        ouput35bytes[3 + i] = entryName_hex_char[i];
    }
    //std::cerr << "Address:" << UcharToHexStr(ouput35bytes, 35) << std::endl;
}

static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    ((std::string *)userp)->append((char *)contents, size * nmemb);
    return size * nmemb;
}

//////////////////////////////////////////////////////////////////
int main(int argc, char **argv)
{
    parse(argc, argv); //parse command line arguments

    json payload;
    payload["Verb"] = intkey_cmd;
    payload["Name"] = intkey_key;
    payload["Value"] = intkey_value;

    std::vector<uint8_t> payload_vect = json::to_cbor(payload);
    std::string payload_str(payload_vect.begin(), payload_vect.end());

    std::string message = "";
    if (mode == "test")
        message = "test";
    else
        message = payload_str;
    std::string message_hash_str = "";
    unsigned char message_hash_char[HASH_SHA256_SIZE];

    unsigned char privateKey[PRIVATE_KEY_SIZE];
    std::string privateKey_str = "";
    size_t publicKey_serilized_len;
    unsigned char publicKey_serilized[PUBLIC_KEY_SERILIZED_SIZE];
    SECP256K1_API::secp256k1_pubkey publicKey;
    std::string publicKey_str = "";

    SECP256K1_API::secp256k1_ecdsa_signature signature;
    std::string signature_serilized_str = "";
    unsigned char signature_serilized[SIGNATURE_SERILIZED_SIZE];

    //default keys:
    publicKey_str = "";//PUBLIC_KEY;
    privateKey_str = "";//PRIVATE_KEY;
    if (publicKey_str.length() > 0 && privateKey_str.length() > 0)
    {
        /* LOAD public keys */
        {
            unsigned char pubkey_char[PUBLIC_KEY_SERILIZED_SIZE];
            HexStrToUchar(pubkey_char, publicKey_str.c_str(), (size_t)PUBLIC_KEY_SERILIZED_SIZE);
            std::cerr << "Parse Public key:" << UcharToHexStr(pubkey_char, PUBLIC_KEY_SERILIZED_SIZE) << std::endl;
            SECP256K1_API::secp256k1_ec_pubkey_parse(ctx, &publicKey, pubkey_char, PUBLIC_KEY_SERILIZED_SIZE);
            std::cerr << "Ok." << std::endl;
        }
        /* LOAD private keys */
        {
            HexStrToUchar(privateKey, privateKey_str.c_str(), (size_t)PRIVATE_KEY_SIZE);
            std::cerr << "Parse private key:" << UcharToHexStr(privateKey, PRIVATE_KEY_SIZE) << std::endl;
            SECP256K1_API::secp256k1_ec_seckey_verify(ctx, privateKey);
            std::cerr << "Ok." << std::endl;
        }
    }
    else
    {
        /* Generate a random key */
        {
            generateRandomBytes(privateKey, PRIVATE_KEY_SIZE);
            privateKey_str = UcharToHexStr(privateKey, PRIVATE_KEY_SIZE);
            std::cerr << "generatePrivateKey:" << privateKey_str << std::endl;
            while (SECP256K1_API::secp256k1_ec_seckey_verify(ctx, privateKey) == 0) //regenerate private key until it is valid
            {
                generateRandomBytes(privateKey, PRIVATE_KEY_SIZE);
                privateKey_str = UcharToHexStr(privateKey, PRIVATE_KEY_SIZE);
                std::cerr << "generatePrivateKey:" << privateKey_str << std::endl;
            }
            SECP256K1_API::secp256k1_ec_seckey_verify(ctx, privateKey);
            std::cerr << "Private key verified.\n->Using:" << privateKey_str << std::endl;
        }

        /* Generate a public key */
        {
            //FAILING:Segmentation fault
            SECP256K1_API::secp256k1_ec_pubkey_create(ctx, &publicKey, privateKey);
            std::cerr << "Public key verified." << std::endl;
            std::cerr << "->Using:" << UcharToHexStr(publicKey.data, PUBLIC_KEY_SIZE) << std::endl;
        }

        /* Serilize public key */
        {
            publicKey_serilized_len = (size_t)PUBLIC_KEY_SERILIZED_SIZE;
            emptyBytes(publicKey_serilized, publicKey_serilized_len);
            SECP256K1_API::secp256k1_ec_pubkey_serialize(ctx, publicKey_serilized, &publicKey_serilized_len, &publicKey, SECP256K1_EC_COMPRESSED);
            publicKey_str = UcharToHexStr(publicKey_serilized, publicKey_serilized_len);
            std::cerr << "Public key serilized ok." << std::endl;
            std::cerr << "->Using:" << publicKey_str << std::endl;
        }
    }

    if (mode == "test")
    {
        std::cerr << "***Test mode***" << std::endl;

        /* Hash message */
        {
            std::cerr << "Message test is ok." << std::endl;
            //std::cerr << "->Using:" << message << std::endl;
            message_hash_str = sha256Data(message);
            //CHECK(message_hash_str == "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08");
            std::cerr << "SHA256 test is ok." << std::endl;
            //std::cerr << "->MSG SHA256:" << message_hash_str << std::endl;
        }

        /* Signing */
        {
            HexStrToUchar(message_hash_char, message_hash_str.c_str(), (size_t)HASH_SHA256_SIZE);
            SECP256K1_API::secp256k1_ecdsa_sign(ctx, &signature, message_hash_char, privateKey, NULL, NULL);
            std::cerr << "Signing test is ok." << std::endl;
        }
        /* Serilize signature compact version*/
        {
            SECP256K1_API::secp256k1_ecdsa_signature_serialize_compact(ctx, signature_serilized, &signature);
            signature_serilized_str = UcharToHexStr(signature_serilized, SIGNATURE_SERILIZED_SIZE);
            //CHECK(signature_serilized_str == "fee5963f29f6fe97ec6fade68556cfe7289d3ebef3b9edf87aadfd3e95cba2100e1cb495f42f4ca50f939322d9a3e7ca04bb9f8fe21d9175bc8a3dd83c885dbf");
            std::cerr << "Serilize signature compact is ok." << std::endl;
            // std::cerr << "->Signature:" << signature_serilized_str << std::endl;
        }
        std::cerr << "***End test mode***" << std::endl;
    }
    else
    {

        
    


        std::cerr << "***Start build real transaction***" << std::endl;
        
        //PROTOBUF
        //init Batch
        BatchList myBatchList;
        //init batch list
        Batch *myBatch = myBatchList.add_batches(); //init the one batch that will be sent
        BatchHeader myBatchHeader;                  //init batch header
        //init Transaction
        //TransactionList transaction_list;                                 //init transaction list
        Transaction *myTransaction = myBatch->add_transactions(); //init the one transaction that will be sent
        TransactionHeader myTransactionHeader;                    //init transaction header

        size_t nonce_size = 10;
        unsigned char Transactionnonce[nonce_size];
        generateRandomBytes(Transactionnonce, nonce_size);
        std::string TxnNonce = UcharToHexStr(Transactionnonce, nonce_size);

        message_hash_str = sha512Data(message);
        unsigned char address[35];
        buildAddress("intkey", intkey_key, address);
        const std::string address_str = UcharToHexStr(address, 35);
        std::cerr << "address_str1:" << address_str << std::endl;

        // buildAddress("intKey", "name", address);
        // address_str = UcharToHexStr(address, 35);
        // std::cerr << "address_str:" << address_str << std::endl;

        //tool to convert into json and print the transaction proto:
        
        google::protobuf::util::JsonPrintOptions json_options;
        json_options.add_whitespace = true;
        json_options.always_print_primitive_fields = true;
        json_options.always_print_enums_as_ints = true;
        json_options.preserve_proto_field_names = true;

        //first build transaction
        //& add all necessary data to protos messages


        
        std::cerr << "Setting transaction header..." << std::endl;
        myTransactionHeader.Clear();
        myTransactionHeader.set_batcher_public_key(publicKey_str); //set batcher pubkey
        myTransactionHeader.set_signer_public_key(publicKey_str);  //set signer pubkey
        myTransactionHeader.set_family_name("intkey");             //the transaction familly to use
        myTransactionHeader.set_family_version("1.0");             //familly version
        myTransactionHeader.set_payload_sha512(message_hash_str);  //set a hash sha512 of the payload
        myTransactionHeader.add_inputs(address_str);               //1cf126cc488cca4cc3565a876f6040f8b73a7b92475be1d0b1bc453f6140fba7183b9a
        myTransactionHeader.add_outputs(address_str);
        myTransactionHeader.set_nonce(TxnNonce); //set nonce of the transaction
        //done transaction header
        myTransaction->Clear();
        std::cerr << "Setting transaction..." << std::endl;
        myTransaction->set_payload(payload_str);
        myTransaction->set_header(myTransactionHeader.SerializePartialAsString());               //build a string of the transaction header
        std::string myTransactionHeader_string = myTransactionHeader.SerializePartialAsString(); //serialize batch header to string

        std::cerr << "Signing transaction header..." << std::endl;
        message_hash_str = sha256Data(myTransactionHeader_string);
        HexStrToUchar(message_hash_char, message_hash_str.c_str(), (size_t)HASH_SHA256_SIZE);
        SECP256K1_API::secp256k1_ecdsa_sign(ctx, &signature, message_hash_char, privateKey, NULL, NULL); //make signature
        SECP256K1_API::secp256k1_ecdsa_signature_serialize_compact(ctx, signature_serilized, &signature);
        signature_serilized_str = UcharToHexStr(signature_serilized, SIGNATURE_SERILIZED_SIZE);
        myTransaction->set_header_signature(signature_serilized_str); //set header signature

        //done transaction

        //add transaction to batch header
        std::cerr << "Setting batch header..." << std::endl;
        myBatchHeader.add_transaction_ids(signature_serilized_str); //add transaction to batch

        //build batch
        myBatchHeader.set_signer_public_key(publicKey_str); //set batch public key
        //myBatchHeader.SerializeToOstream()
        std::string myBatchHeader_string = myBatchHeader.SerializePartialAsString(); //serialize batch header to string
        std::cerr << "Setting batch..." << std::endl;
        myBatch->set_header(myBatchHeader_string); //set header

        std::cerr << "Signing batch header..." << std::endl;
        message_hash_str = sha256Data(myBatchHeader_string);
        HexStrToUchar(message_hash_char, message_hash_str.c_str(), (size_t)HASH_SHA256_SIZE);
        SECP256K1_API::secp256k1_ecdsa_sign(ctx, &signature, message_hash_char, privateKey, NULL, NULL); //make signature
        SECP256K1_API::secp256k1_ecdsa_signature_serialize_compact(ctx, signature_serilized, &signature);
        signature_serilized_str = UcharToHexStr(signature_serilized, SIGNATURE_SERILIZED_SIZE);

        myBatch->set_header_signature(signature_serilized_str);

        std::cerr << "***Done build real transaction***" << std::endl;

        std::cerr << "Sending batch list to stdout..." << std::endl;
        //myBatchList.SerializePartialToOstream(&std::cout);
        std::cerr << std::endl;

    
        //send transaction

        std::string batch_string = myBatchList.SerializePartialAsString();
        CURL *curl;
        CURLcode res;
        struct curl_slist *headers = NULL;
        std::string readBuffer;
        curl = curl_easy_init();
        if (curl && strcmp(batch_api_endpoint.c_str(), "") != 0)
        {

            curl_easy_setopt(curl, CURLOPT_URL, batch_api_endpoint.c_str());
            headers = curl_slist_append(headers, "Content-Type: application/octet-stream");
            curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

            //curl_easy_setopt(curl, CURLOPT_POST, 1L);
            curl_easy_setopt(curl, CURLOPT_POSTFIELDS, batch_string.c_str());
            curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE, -1L);

            curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
            curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

            //curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
            res = curl_easy_perform(curl);
            curl_easy_cleanup(curl);

            std::cout << "***Transaction sended***" << std::endl;
            std::cout << "STATUS CODE:" << res << std::endl;
            std::cout << readBuffer << std::endl;
        }
        curl_global_cleanup();
    }

    return 0;
}
