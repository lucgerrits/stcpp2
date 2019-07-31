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
#include <assert.h>
#include <string>

#include "common.h"

#include "cxxopts/include/cxxopts.hpp" //to parse arguments

//#include "cbor-cpp/src/encoder.h"
//#include "cbor-cpp/src/decoder.h"
//#include "cbor-cpp/src/output_dynamic.h"

#include "nlohmann/json.hpp"
using json = nlohmann::json;

//typedef unsigned char byte; //is missing for some case

//END TOP MAIN

struct SawtoothKeys
{
    std::string privKey = PRIVATE_KEY;
    std::string pubKey = PUBLIC_KEY;
    SECP256K1_API::secp256k1_pubkey publicKey;
    unsigned char privateKey[PRIVATE_KEY_SIZE];
    unsigned char publicKey_serilized[PUBLIC_KEY_SERILIZED_SIZE];
};
struct Arg_Options
{
    std::string arg_mode;
    std::string arg_command = "";
    std::string api_endpoint;
    bool isverbose = false;

    std::string arg_key = "";
    int arg_value = -1;

    std::string arg_owner_lastname = "";
    std::string arg_owner_name = "";
    std::string arg_owner_address = "";
    std::string arg_owner_country = "";
    std::string arg_owner_contact = "";
    std::string arg_owner_picture = "";

    std::string arg_car_brand = "";
    std::string arg_car_type = "";
    std::string arg_car_licence = "";

    std::string eth_mode;
    std::string eth_create_account_alias = "";

    std::string privKey;
    std::string pubKey;
    std::string carprivKey;
    std::string carpubKey;
};
//////////////////////////////////////////////////////////////////
//global variables:
static SECP256K1_API::secp256k1_context *ctx = SECP256K1_API::secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
//////////////////////////////////////////////////////////////////
//Functions:

//following the example: https://github.com/jarro2783/cxxopts/blob/master/src/example.cpp
cxxopts::ParseResult
parse(int argc, char *argv[], Arg_Options &arg_options)
{
    try
    {
        cxxopts::Options options(argv[0], " - example command line options");
        options
            .positional_help("[optional args]")
            .show_positional_help();

        options
            .allow_unrecognised_options()
            .add_options()
            //Common options
            //help
            ("help", "Print help")
            // mode
            ("mode", "Mode: test, intkey, cartp or eth", cxxopts::value<std::string>())
            // url endpoint
            ("url", "Sawtooth REST API endpoint.", cxxopts::value<std::string>()) //Is different for eth ?
            //Command for transaction processor
            ("cmd", "Command used. For Inkey are: set, dec or inc. For cartp: new_car, new_owner, crash", cxxopts::value<std::string>())
            //
            ("privatekey", "Private key to use", cxxopts::value<std::string>())
            //
            ("publickey", "Public key to use", cxxopts::value<std::string>())
            //
            ("carprivatekey", "Private key to use for the car", cxxopts::value<std::string>())
            //
            ("carpublickey", "Public key to use for the car", cxxopts::value<std::string>());

        options.add_options("Inkey")
            //Inkey
            //Inkey key
            ("key", "Inkey key", cxxopts::value<std::string>())
            //Inkey value
            ("value", "Inkey value", cxxopts::value<int>());

        options.add_options("Cartp:new_car")
            //Cartp
            //cartp new_car
            ("car_brand", "Car brand", cxxopts::value<std::string>())
            //
            ("car_type", "Car type", cxxopts::value<std::string>())
            //
            ("car_licence", "Car licence", cxxopts::value<std::string>())
            //
            ;
        options.add_options("Cartp:new_owner")
            //Cartp
            //cartp new_owner
            ("owner_lastname", "Car owner lastname", cxxopts::value<std::string>())
            //
            ("owner_name", "Car owner name", cxxopts::value<std::string>())
            //
            ("owner_address", "Car owner address", cxxopts::value<std::string>())
            //
            ("owner_country", "Car owner country", cxxopts::value<std::string>())
            //
            ("owner_contact", "Car owner contact", cxxopts::value<std::string>())
            //
            ("owner_picture", "Car owner picture", cxxopts::value<std::string>())
            //
            ;
        options.add_options("Ethereum")
            //eth create account
            ("create", "Create Ethereum account", cxxopts::value<std::string>());

        options.add_options("Other")("v,verbose", "verbose");
        //options.parse_positional({"input", "output", "positional"});

        auto result = options.parse(argc, argv);

        if (result.count("help"))
        {
            std::cout << options.help({"", "Inkey", "Cartp:new_car", "Cartp:new_owner", "Other"}) << std::endl;
            exit(0);
        }
        if (result.count("mode"))
        {
            //go for test mode
            arg_options.arg_mode = result["mode"].as<std::string>();
        }
        else
        {
            std::cout << "ERROR: mode is required." << std::endl;
            exit(0);
        }
        if (result.count("cmd"))
        {
            arg_options.arg_command = result["cmd"].as<std::string>();
        }
        if (result.count("privatekey"))
        {
            arg_options.privKey = result["privatekey"].as<std::string>();
        }
        if (result.count("publickey"))
        {
            arg_options.pubKey = result["publickey"].as<std::string>();
        }
        if (result.count("carprivatekey"))
        {
            arg_options.carprivKey = result["carprivatekey"].as<std::string>();
        }
        if (result.count("carpublickey"))
        {
            arg_options.carpubKey = result["carpublickey"].as<std::string>();
        }
        //intkey stuff
        if (result.count("key"))
        {
            arg_options.arg_key = result["key"].as<std::string>();
        }
        if (result.count("value"))
        {
            //go for test mode
            arg_options.arg_value = result["value"].as<int>();
        }
        //cartp stuff
        if (result.count("owner_lastname"))
        {
            arg_options.arg_owner_lastname = result["owner_lastname"].as<std::string>();
        }
        if (result.count("owner_name"))
        {
            arg_options.arg_owner_name = result["owner_name"].as<std::string>();
        }
        if (result.count("owner_address"))
        {
            arg_options.arg_owner_address = result["owner_address"].as<std::string>();
        }
        if (result.count("owner_country"))
        {
            arg_options.arg_owner_country = result["owner_country"].as<std::string>();
        }
        if (result.count("owner_contact"))
        {
            arg_options.arg_owner_contact = result["owner_contact"].as<std::string>();
        }
        if (result.count("owner_picture"))
        {
            arg_options.arg_owner_picture = result["owner_picture"].as<std::string>();
        }
        if (result.count("car_brand"))
        {
            arg_options.arg_car_brand = result["car_brand"].as<std::string>();
        }
        if (result.count("car_type"))
        {
            arg_options.arg_car_type = result["car_type"].as<std::string>();
        }
        if (result.count("car_licence"))
        {
            arg_options.arg_car_licence = result["car_licence"].as<std::string>();
        }

        //eth stuff
        if (result.count("create"))
        {
            arg_options.eth_mode = "create_account";
            arg_options.eth_create_account_alias = result["create"].as<std::string>();
        }
        if (result.count("url"))
        {
            arg_options.api_endpoint = result["url"].as<std::string>(); //"http://134.59.230.101:8081/batches"
        }
        if (result.count("v"))
        {
            arg_options.isverbose = true;
        }
        return result;
    }
    catch (const cxxopts::OptionException &e)
    {
        std::cout << "ERROR: parsing options: " << e.what() << std::endl;
        exit(1);
    }
}

//////////////////////////////////////////////////////////////////
int main(int argc, char **argv)
{
    SawtoothKeys userKeys;
    SawtoothKeys carKeys;
    Arg_Options options;
    parse(argc, argv, options); //parse command line arguments

    std::string message = "";
    std::string message_hash_str = "";
    unsigned char message_hash_char[HASH_SHA256_SIZE];

    SECP256K1_API::secp256k1_ecdsa_signature signature;
    std::string signature_serilized_str = "";
    unsigned char signature_serilized[SIGNATURE_SERILIZED_SIZE];

    //default keys:
    if (!options.privKey.empty() && !options.pubKey.empty())
    {
        std::cout << "***User keys Given by command line***" << std::endl;
        userKeys.privKey = options.privKey;
        userKeys.pubKey = options.pubKey;
    }
    else
    {
        if (options.isverbose)
            std::cout << "***Using user default private and public keys***" << std::endl;
    }
    CHECK(LoadKeys(ctx, userKeys.privateKey, userKeys.privKey, userKeys.publicKey, userKeys.publicKey_serilized, userKeys.pubKey, options.isverbose) == 1);

    //default keys:
    if (!options.carprivKey.empty() && !options.carpubKey.empty())
    {
        std::cout << "***Car keys Given by command line***" << std::endl;
        carKeys.privKey = options.carprivKey;
        carKeys.pubKey = options.carpubKey;
    }
    else
    {
        if (options.isverbose)
            std::cout << "***Using car default private and public keys***" << std::endl;
    }
    CHECK(LoadKeys(ctx, carKeys.privateKey, carKeys.privKey, carKeys.publicKey, carKeys.publicKey_serilized, carKeys.pubKey, options.isverbose) == 1);

    if (!strcmp(options.arg_mode.c_str(), "test"))
    {
        std::cout << "***Test mode***" << std::endl;
        message = "test";

        /* Hash message */
        {
            std::cout << "Message test is ok." << std::endl;
            //std::cout << "->Using:" << message << std::endl;
            message_hash_str = sha256Data(message);
            CHECK(message_hash_str == "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08");
            std::cout << "SHA256 test is ok." << std::endl;
            //std::cout << "->MSG SHA256:" << message_hash_str << std::endl;
        }

        /* Signing */
        {
            HexStrToUchar(message_hash_char, message_hash_str.c_str(), (size_t)HASH_SHA256_SIZE);
            CHECK(SECP256K1_API::secp256k1_ecdsa_sign(ctx, &signature, message_hash_char, userKeys.privateKey, NULL, NULL) == 1);
            std::cout << "Signing test is ok." << std::endl;
        }
        /* Serilize signature compact version*/
        {
            CHECK(SECP256K1_API::secp256k1_ecdsa_signature_serialize_compact(ctx, signature_serilized, &signature) == 1);
            signature_serilized_str = UcharToHexStr(signature_serilized, SIGNATURE_SERILIZED_SIZE);
            CHECK(signature_serilized_str == "fee5963f29f6fe97ec6fade68556cfe7289d3ebef3b9edf87aadfd3e95cba2100e1cb495f42f4ca50f939322d9a3e7ca04bb9f8fe21d9175bc8a3dd83c885dbf");
            std::cout << "Serilize signature compact is ok." << std::endl;
            // std::cout << "->Signature:" << signature_serilized_str << std::endl;
        }
        std::cout << "***End test mode***" << std::endl;
    }
    else if (!strcmp(options.arg_mode.c_str(), "intkey"))
    {
        std::cout << "***intkey mode***" << std::endl;
        std::string tp_family = "intkey";
        if (options.isverbose)
            std::cout << "***Start build transaction***" << std::endl;
        if (!strcmp(options.arg_command.c_str(), "") || !strcmp(options.arg_command.c_str(), "") || options.arg_value == -1)
        {
            std::cout << "ERROR: key, value and cmd is required." << std::endl;
            exit(1);
        }
        json payload;
        payload["Verb"] = options.arg_command;
        payload["Name"] = options.arg_key;
        payload["Value"] = options.arg_value;
        std::vector<uint8_t> payload_vect = json::to_cbor(payload);
        std::string payload_str(payload_vect.begin(), payload_vect.end());
        message = payload_str;

        //PROTOBUF
        //init Batch
        BatchList myBatchList;                      //init batch list
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
        buildIntkeyAddress(tp_family, options.arg_key, address);
        const std::string address_str = UcharToHexStr(address, 35);
        if (options.isverbose)
            std::cout << "address used:" << address_str << std::endl;

        //first build transaction
        //& add all necessary data to protos messages
        if (options.isverbose)
            std::cout << "Setting transaction header..." << std::endl;
        myTransactionHeader.Clear();
        myTransactionHeader.set_batcher_public_key(carKeys.pubKey); //set batcher pubkey
        myTransactionHeader.set_signer_public_key(userKeys.pubKey); //set signer pubkey
        myTransactionHeader.set_family_name(tp_family);             //the transaction familly to use
        myTransactionHeader.set_family_version("1.0");              //familly version
        myTransactionHeader.set_payload_sha512(message_hash_str);   //set a hash sha512 of the payload
        myTransactionHeader.add_inputs(address_str);                //1cf126cc488cca4cc3565a876f6040f8b73a7b92475be1d0b1bc453f6140fba7183b9a
        myTransactionHeader.add_outputs(address_str);
        myTransactionHeader.set_nonce(TxnNonce); //set nonce of the transaction
        //done transaction header
        myTransaction->Clear();
        if (options.isverbose)
            std::cout << "Setting transaction..." << std::endl;
        myTransaction->set_payload(message);
        myTransaction->set_header(myTransactionHeader.SerializePartialAsString());               //build a string of the transaction header
        std::string myTransactionHeader_string = myTransactionHeader.SerializePartialAsString(); //serialize batch header to string

        if (options.isverbose)
            std::cout << "Signing transaction header..." << std::endl;
        message_hash_str = sha256Data(myTransactionHeader_string);
        HexStrToUchar(message_hash_char, message_hash_str.c_str(), (size_t)HASH_SHA256_SIZE);
        CHECK(SECP256K1_API::secp256k1_ecdsa_sign(ctx, &signature, message_hash_char, userKeys.privateKey, NULL, NULL) == 1); //make signature
        CHECK(SECP256K1_API::secp256k1_ecdsa_signature_serialize_compact(ctx, signature_serilized, &signature) == 1);
        signature_serilized_str = UcharToHexStr(signature_serilized, SIGNATURE_SERILIZED_SIZE);
        myTransaction->set_header_signature(signature_serilized_str); //set header signature

        //done transaction

        //add transaction to batch header
        if (options.isverbose)
            std::cout << "Setting batch header..." << std::endl;
        myBatchHeader.add_transaction_ids(signature_serilized_str); //add transaction to batch

        //build batch
        myBatchHeader.set_signer_public_key(carKeys.pubKey); //set batch public key
        //myBatchHeader.SerializeToOstream()
        std::string myBatchHeader_string = myBatchHeader.SerializePartialAsString(); //serialize batch header to string
        if (options.isverbose)
            std::cout << "Setting batch..." << std::endl;
        myBatch->set_header(myBatchHeader_string); //set header

        if (options.isverbose)
            std::cout << "Signing batch header..." << std::endl;
        message_hash_str = sha256Data(myBatchHeader_string);
        HexStrToUchar(message_hash_char, message_hash_str.c_str(), (size_t)HASH_SHA256_SIZE);
        CHECK(SECP256K1_API::secp256k1_ecdsa_sign(ctx, &signature, message_hash_char, carKeys.privateKey, NULL, NULL) == 1); //make signature
        CHECK(SECP256K1_API::secp256k1_ecdsa_signature_serialize_compact(ctx, signature_serilized, &signature) == 1);
        signature_serilized_str = UcharToHexStr(signature_serilized, SIGNATURE_SERILIZED_SIZE);

        myBatch->set_header_signature(signature_serilized_str);

        if (options.isverbose)
            std::cout << "***Done build real transaction***" << std::endl;

        //send transaction
        std::string data_string = myBatchList.SerializePartialAsString();
        if (!strcmp(options.api_endpoint.c_str(), ""))
        {
            std::cout << "WARNING: url is required to send the transaction." << std::endl;
        }
        else
        {
            std::cout << "Sending batch list to:" << options.api_endpoint << "" << std::endl;
            CHECK(sendData(data_string, options.api_endpoint, options.isverbose) == 1);
        }
    }
    else if (!strcmp(options.arg_mode.c_str(), "cartp"))
    {
        std::cout << "***cartp mode***" << std::endl;
        std::string tp_family = "cartp";
        if (options.isverbose)
            std::cout << "***Start build transaction***" << std::endl;

        if (options.isverbose)
            std::cout << "Setting transaction payload..." << std::endl;
        if (options.arg_command.empty())
        {
            std::cout << "ERROR: arg_command, ";
            std::cout << "is required." << std::endl;
            exit(1);
        }
        json payload;
        unsigned char address[35];

        //following payload fields are always required
        payload["tnx_cmd"] = options.arg_command;
        payload["car_id"] = carKeys.pubKey;
        if (!strcmp(options.arg_command.c_str(), "new_car"))
        {
            //set payload for the command new_car
            if (options.arg_car_brand.empty() ||
                options.arg_car_type.empty() ||
                options.arg_car_licence.empty())
            {
                std::cout << "ERROR: ";
                std::cout << "car_brand, ";
                std::cout << "car_type, ";
                std::cout << "car_licence, ";
                std::cout << "is required." << std::endl;
                exit(1);
            }
            payload["car_brand"] = options.arg_car_brand;
            payload["car_type"] = options.arg_car_type;
            payload["car_licence"] = options.arg_car_licence;
            buildCarTPAddress(tp_family, "car", carKeys.pubKey, address);
        }
        else if (!strcmp(options.arg_command.c_str(), "new_owner"))
        {
            //set payload for the command new_owner
            if (options.arg_owner_picture.empty() ||
                options.arg_owner_lastname.empty() ||
                options.arg_owner_name.empty() ||
                options.arg_owner_address.empty() ||
                options.arg_owner_country.empty() ||
                options.arg_owner_contact.empty())
            {
                std::cout << "ERROR: ";
                std::cout << "owner_picture, ";
                std::cout << "owner_lastname, ";
                std::cout << "owner_name, ";
                std::cout << "owner_address, ";
                std::cout << "owner_country, ";
                std::cout << "owner_contact ";
                std::cout << "is required." << std::endl;
                exit(1);
            }
            payload["owner_id"] = userKeys.pubKey;
            //load file to Uchar then transform to hex
            std::ifstream infile(options.arg_owner_picture, std::ios::binary);
            std::string picture_content((std::istreambuf_iterator<char>(infile)),
                                        (std::istreambuf_iterator<char>()));
            payload["owner_picture"] = UcharToHexStr((unsigned char *)picture_content.c_str(), picture_content.length());
            payload["owner_picture_ext"] = options.arg_owner_picture.substr(options.arg_owner_picture.find_last_of(".") + 1); //".png";

            payload["owner_lastname"] = options.arg_owner_lastname;
            payload["owner_name"] = options.arg_owner_name;
            payload["owner_address"] = options.arg_owner_address;
            payload["owner_country"] = options.arg_owner_country;
            payload["owner_contact"] = options.arg_owner_contact;
            buildCarTPAddress(tp_family, "owner", carKeys.pubKey, address);
        }
        else
        {
            std::cout << "ERROR: Command " << options.arg_command << " unknown." << std::endl;
            exit(1);
        }
        const std::string address_str = UcharToHexStr(address, 35);
        if (options.isverbose)
            std::cout << "Address used:" << address_str << std::endl;
        if (options.isverbose)
            std::cout << "Encoding transaction payload..." << std::endl;
        std::vector<uint8_t> payload_vect = json::to_cbor(payload);
        std::string payload_str(payload_vect.begin(), payload_vect.end());
        message = payload_str;

        // message = "{\"tnx_cmd\": \"" + arg_command + "\", \"car_id\":\"" + publicKey_str + "\", \"owner\":\"" + arg_owner + "\", \"owner_picture\":\"" + UcharToHexStr((unsigned char *)picture_content.c_str(), picture_content.length()) + "\", \"owner_picture_ext\":\"" + arg_owner_pic.substr(arg_owner_pic.find_last_of(".") + 1) + "\"}";
        // cbor::output_dynamic output;
        // cbor::encoder encoder(output);
        // encoder.write_string("tnx_cmd");
        // encoder.write_string(arg_command);
        // encoder.write_string(message);

        // message = UcharToHexStr(output.data(), output.size());

        //PROTOBUF
        //init Batch
        BatchList myBatchList;                      //init batch list
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

        //first build transaction
        //& add all necessary data to protos messages
        if (options.isverbose)
            std::cout << "Setting transaction header..." << std::endl;
        myTransactionHeader.Clear();
        myTransactionHeader.set_batcher_public_key(carKeys.pubKey); //set batcher pubkey
        myTransactionHeader.set_signer_public_key(userKeys.pubKey); //set signer pubkey
        myTransactionHeader.set_family_name(tp_family);             //the transaction familly to use
        myTransactionHeader.set_family_version("1.0");              //familly version
        myTransactionHeader.set_payload_sha512(message_hash_str);   //set a hash sha512 of the payload
        myTransactionHeader.add_inputs(address_str);                //1cf126cc488cca4cc3565a876f6040f8b73a7b92475be1d0b1bc453f6140fba7183b9a
        myTransactionHeader.add_outputs(address_str);
        myTransactionHeader.set_nonce(TxnNonce); //set nonce of the transaction
        //done transaction header
        myTransaction->Clear();
        if (options.isverbose)
            std::cout << "Setting transaction..." << std::endl;
        myTransaction->set_payload(message);
        myTransaction->set_header(myTransactionHeader.SerializePartialAsString());               //build a string of the transaction header
        std::string myTransactionHeader_string = myTransactionHeader.SerializePartialAsString(); //serialize batch header to string

        if (options.isverbose)
            std::cout << "Signing transaction header..." << std::endl;
        message_hash_str = sha256Data(myTransactionHeader_string);
        HexStrToUchar(message_hash_char, message_hash_str.c_str(), (size_t)HASH_SHA256_SIZE);
        CHECK(SECP256K1_API::secp256k1_ecdsa_sign(ctx, &signature, message_hash_char, userKeys.privateKey, NULL, NULL) == 1); //make signature
        CHECK(SECP256K1_API::secp256k1_ecdsa_signature_serialize_compact(ctx, signature_serilized, &signature) == 1);
        signature_serilized_str = UcharToHexStr(signature_serilized, SIGNATURE_SERILIZED_SIZE);
        myTransaction->set_header_signature(signature_serilized_str); //set header signature

        //done transaction

        //add transaction to batch header
        if (options.isverbose)
            std::cout << "Setting batch header..." << std::endl;
        myBatchHeader.add_transaction_ids(signature_serilized_str); //add transaction to batch

        //build batch
        myBatchHeader.set_signer_public_key(carKeys.pubKey); //set batch public key
        //myBatchHeader.SerializeToOstream()
        std::string myBatchHeader_string = myBatchHeader.SerializePartialAsString(); //serialize batch header to string
        if (options.isverbose)
            std::cout << "Setting batch..." << std::endl;
        myBatch->set_header(myBatchHeader_string); //set header

        if (options.isverbose)
            std::cout << "Signing batch header..." << std::endl;
        message_hash_str = sha256Data(myBatchHeader_string);
        HexStrToUchar(message_hash_char, message_hash_str.c_str(), (size_t)HASH_SHA256_SIZE);
        CHECK(SECP256K1_API::secp256k1_ecdsa_sign(ctx, &signature, message_hash_char, carKeys.privateKey, NULL, NULL) == 1); //make signature
        CHECK(SECP256K1_API::secp256k1_ecdsa_signature_serialize_compact(ctx, signature_serilized, &signature) == 1);
        signature_serilized_str = UcharToHexStr(signature_serilized, SIGNATURE_SERILIZED_SIZE);

        myBatch->set_header_signature(signature_serilized_str);
        //myBatch->set_trace(true); //more logs in sawtooth

        // std::cout << "myTransactionHeader" << std::endl;
        // printProtoJson(myTransactionHeader);
        // std::cout << "myTransaction" << std::endl;
        // printProtoJson(*myTransaction);
        // std::cout << "myBatchHeader" << std::endl;
        // printProtoJson(myBatchHeader);
        // std::cout << "myBatch" << std::endl;
        // printProtoJson(*myBatch);

        if (options.isverbose)
            std::cout << "***Done build real transaction***" << std::endl;

        //send transaction
        std::string data_string = myBatchList.SerializePartialAsString();
        if (!strcmp(options.api_endpoint.c_str(), ""))
        {
            std::cout << "WARNING: url is required to send the transaction." << std::endl;
        }
        else
        {
            std::cout << "Sending batch list to:" << options.api_endpoint << "" << std::endl;
            CHECK(sendData(data_string, options.api_endpoint, options.isverbose) == 1);
        }
    }
    else if (!strcmp(options.arg_mode.c_str(), "eth"))
    {
        std::cout << "***ethereum mode***" << std::endl;
        // if (isverbose)
        //     std::cout << "***Start build transaction***" << std::endl;

        //- Create eth account
        //- build sol contract, compile
        //- deploy contract
        //- call contract
        //- use transaction id

        if (!strcmp(options.eth_mode.c_str(), "create_account"))
        {
            std::cout << "***create account***" << std::endl;

            if (!strcmp(options.eth_create_account_alias.c_str(), ""))
            {
                std::cout << "ERROR: to create an account you need to give an alias" << std::endl;
            }
            else
            {
                options.eth_create_account_alias = "luc";

                SethTransaction mySethTransaction;
                mySethTransaction.set_transaction_type(SethTransaction_TransactionType_CREATE_EXTERNAL_ACCOUNT);
                CreateExternalAccountTxn myExternalAccount = mySethTransaction.create_external_account();
                myExternalAccount.set_to("");

                //newAcctAddr
                std::string EvmAddr = "";
            }
        }
        else if (!strcmp(options.arg_mode.c_str(), "other eth mode"))
        {
        }
    }
    else if (!strcmp(options.arg_mode.c_str(), "genkeys"))
    {
        std::cout << "***Generating keys***" << std::endl;

        GenerateKeyPair(ctx, userKeys.privateKey, userKeys.privKey, userKeys.publicKey, userKeys.publicKey_serilized, userKeys.pubKey, options.isverbose);
        std::cout << std::left;
        std::cout << std::setw(15) << "Private Key: " << userKeys.privKey << std::endl;
        std::cout << std::setw(15) << "Public Key: " << userKeys.pubKey << std::endl;
    }
    else
    {
        std::cout << "Unknown mode \"" << options.arg_mode << "\" . Only: 'test' or 'eth'" << std::endl;
        exit(1);
    }
    //std::cout << "Done." << std::endl;
    return 0;
}
