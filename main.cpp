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

#include "nlohmann/json.hpp"
using json = nlohmann::json;

//typedef unsigned char byte; //is missing for some case

//END TOP MAIN

//////////////////////////////////////////////////////////////////
//global variables:
static SECP256K1_API::secp256k1_context *ctx = SECP256K1_API::secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
std::string arg_mode = "";
std::string eth_mode = "";
std::string eth_create_account_alias = "";
bool isverbose = false;
std::string arg_command = "";
std::string arg_key = "";
std::string arg_owner = "";
std::string arg_owner_pic = "";
size_t picture_buffer_size = MAX_PICTURE_BUFFER_SIZE;
int arg_value = -1;
std::string batch_api_endpoint = "";
std::string initpubkey = "";
std::string initprivkey = "";
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
            .add_options()
            //Common options
            //help
            ("help", "Print help")
            // mode
            ("mode", "Mode: test, intkey, cartp or eth", cxxopts::value<std::string>())
            // url endpoint
            ("url", "Sawtooth REST API endpoint.", cxxopts::value<std::string>()) //Is different for eth ?
            //Command for transaction processor
            ("cmd", "Command used. For Inkey are: set, dec or inc. For cartp: set_owner", cxxopts::value<std::string>())
            //
            ("privatekey", "Private key to use", cxxopts::value<std::string>())
            //
            ("publickey", "Public key to use", cxxopts::value<std::string>())
            //
            ;

        options.add_options("Inkey")
            //Inkey
            //Inkey key
            ("key", "Inkey key", cxxopts::value<std::string>())
            //Inkey value
            ("value", "Inkey value", cxxopts::value<int>());

        options.add_options("Cartp")
            //Cartp
            //cartp owner
            ("owner", "Car owner", cxxopts::value<std::string>())
            //cartp owner picture
            ("owner_pic", "Car owner picture", cxxopts::value<std::string>())
            //cartp owner picture size no limit
            ("disable_owner_pic_size", "Disable car owner picture size");

        options.add_options("Ethereum")
            //eth create account
            ("create", "Create Ethereum account", cxxopts::value<std::string>());

        options.add_options("Other")("v,verbose", "verbose");
        options.parse_positional({"input", "output", "positional"});

        auto result = options.parse(argc, argv);

        if (result.count("help"))
        {
            std::cout << options.help({"", "Inkey", "Cartp", "Other"}) << std::endl;
            exit(0);
        }
        if (result.count("mode"))
        {
            //go for test mode
            arg_mode = result["mode"].as<std::string>();
        }
        else
        {
            std::cout << "ERROR: mode is required." << std::endl;
            exit(0);
        }
        if (result.count("cmd"))
        {
            arg_command = result["cmd"].as<std::string>();
        }
        if (result.count("privatekey"))
        {
            initprivkey = result["privatekey"].as<std::string>();
        }
        if (result.count("publickey"))
        {
            initpubkey = result["publickey"].as<std::string>();
        }
        if (result.count("key"))
        {
            arg_key = result["key"].as<std::string>();
        }
        if (result.count("value"))
        {
            //go for test mode
            arg_value = result["value"].as<int>();
        }
        if (result.count("owner"))
        {
            arg_owner = result["owner"].as<std::string>();
        }
        if (result.count("owner_pic"))
        {
            arg_owner_pic = result["owner_pic"].as<std::string>();
        }
        if (result.count("disable_owner_pic_size"))
        {
            picture_buffer_size = std::numeric_limits<std::size_t>::max();
        }
        if (result.count("create"))
        {
            eth_mode = "create_account";
            eth_create_account_alias = result["create"].as<std::string>();
        }
        if (result.count("url"))
        {
            batch_api_endpoint = result["url"].as<std::string>(); //"http://134.59.230.101:8081/batches"
        }
        if (result.count("v"))
        {
            isverbose = true;
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
    parse(argc, argv); //parse command line arguments

    std::string message = "";
    std::string message_hash_str = "";
    unsigned char message_hash_char[HASH_SHA256_SIZE];

    unsigned char privateKey[PRIVATE_KEY_SIZE];
    std::string privateKey_str = "";
    unsigned char publicKey_serilized[PUBLIC_KEY_SERILIZED_SIZE];
    SECP256K1_API::secp256k1_pubkey publicKey;
    std::string publicKey_str = "";

    SECP256K1_API::secp256k1_ecdsa_signature signature;
    std::string signature_serilized_str = "";
    unsigned char signature_serilized[SIGNATURE_SERILIZED_SIZE];

    //default keys:
    publicKey_str = PUBLIC_KEY;
    privateKey_str = PRIVATE_KEY;
        std::cout << "initprivkey" << initprivkey << std::endl;
    if (!initprivkey.empty() && !initpubkey.empty())
    {
        std::cout << "***Keys Given by command line***" << std::endl;
        privateKey_str = initprivkey;
        publicKey_str = initpubkey;
    }
    else
    {
        std::cout << "***Using default private and public keys***" << std::endl;
    }
    LoadKeys(ctx, privateKey, privateKey_str, publicKey, publicKey_serilized, publicKey_str, isverbose);

    if (!strcmp(arg_mode.c_str(), "test"))
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
            CHECK(SECP256K1_API::secp256k1_ecdsa_sign(ctx, &signature, message_hash_char, privateKey, NULL, NULL) == 1);
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
    else if (!strcmp(arg_mode.c_str(), "intkey"))
    {
        std::cout << "***intkey mode***" << std::endl;
        std::string tp_family = "intkey";
        if (isverbose)
            std::cout << "***Start build transaction***" << std::endl;
        if (!strcmp(arg_command.c_str(), "") || !strcmp(arg_command.c_str(), "") || arg_value == -1)
        {
            std::cout << "ERROR: key, value and cmd is required." << std::endl;
            exit(0);
        }
        json payload;
        payload["Verb"] = arg_command;
        payload["Name"] = arg_key;
        payload["Value"] = arg_value;
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
        buildAddress(tp_family, arg_key, address);
        const std::string address_str = UcharToHexStr(address, 35);
        if (isverbose)
            std::cout << "address used:" << address_str << std::endl;

        // buildAddress(tp_family, "name", address);
        // address_str = UcharToHexStr(address, 35);
        // std::cout << "address_str:" << address_str << std::endl;

        //tool to convert into json and print the transaction proto:
        google::protobuf::util::JsonPrintOptions json_options;
        json_options.add_whitespace = true;
        json_options.always_print_primitive_fields = true;
        json_options.always_print_enums_as_ints = true;
        json_options.preserve_proto_field_names = true;

        //first build transaction
        //& add all necessary data to protos messages
        if (isverbose)
            std::cout << "Setting transaction header..." << std::endl;
        myTransactionHeader.Clear();
        myTransactionHeader.set_batcher_public_key(publicKey_str); //set batcher pubkey
        myTransactionHeader.set_signer_public_key(publicKey_str);  //set signer pubkey
        myTransactionHeader.set_family_name(tp_family);            //the transaction familly to use
        myTransactionHeader.set_family_version("1.0");             //familly version
        myTransactionHeader.set_payload_sha512(message_hash_str);  //set a hash sha512 of the payload
        myTransactionHeader.add_inputs(address_str);               //1cf126cc488cca4cc3565a876f6040f8b73a7b92475be1d0b1bc453f6140fba7183b9a
        myTransactionHeader.add_outputs(address_str);
        myTransactionHeader.set_nonce(TxnNonce); //set nonce of the transaction
        //done transaction header
        myTransaction->Clear();
        if (isverbose)
            std::cout << "Setting transaction..." << std::endl;
        myTransaction->set_payload(payload_str);
        myTransaction->set_header(myTransactionHeader.SerializePartialAsString());               //build a string of the transaction header
        std::string myTransactionHeader_string = myTransactionHeader.SerializePartialAsString(); //serialize batch header to string

        if (isverbose)
            std::cout << "Signing transaction header..." << std::endl;
        message_hash_str = sha256Data(myTransactionHeader_string);
        HexStrToUchar(message_hash_char, message_hash_str.c_str(), (size_t)HASH_SHA256_SIZE);
        CHECK(SECP256K1_API::secp256k1_ecdsa_sign(ctx, &signature, message_hash_char, privateKey, NULL, NULL) == 1); //make signature
        CHECK(SECP256K1_API::secp256k1_ecdsa_signature_serialize_compact(ctx, signature_serilized, &signature) == 1);
        signature_serilized_str = UcharToHexStr(signature_serilized, SIGNATURE_SERILIZED_SIZE);
        myTransaction->set_header_signature(signature_serilized_str); //set header signature

        //done transaction

        //add transaction to batch header
        if (isverbose)
            std::cout << "Setting batch header..." << std::endl;
        myBatchHeader.add_transaction_ids(signature_serilized_str); //add transaction to batch

        //build batch
        myBatchHeader.set_signer_public_key(publicKey_str); //set batch public key
        //myBatchHeader.SerializeToOstream()
        std::string myBatchHeader_string = myBatchHeader.SerializePartialAsString(); //serialize batch header to string
        if (isverbose)
            std::cout << "Setting batch..." << std::endl;
        myBatch->set_header(myBatchHeader_string); //set header

        if (isverbose)
            std::cout << "Signing batch header..." << std::endl;
        message_hash_str = sha256Data(myBatchHeader_string);
        HexStrToUchar(message_hash_char, message_hash_str.c_str(), (size_t)HASH_SHA256_SIZE);
        CHECK(SECP256K1_API::secp256k1_ecdsa_sign(ctx, &signature, message_hash_char, privateKey, NULL, NULL) == 1); //make signature
        CHECK(SECP256K1_API::secp256k1_ecdsa_signature_serialize_compact(ctx, signature_serilized, &signature) == 1);
        signature_serilized_str = UcharToHexStr(signature_serilized, SIGNATURE_SERILIZED_SIZE);

        myBatch->set_header_signature(signature_serilized_str);

        if (isverbose)
            std::cout << "***Done build real transaction***" << std::endl;

        //send transaction
        std::string data_string = myBatchList.SerializePartialAsString();
        if (!strcmp(batch_api_endpoint.c_str(), ""))
        {
            std::cout << "WARNING: url is required to send the transaction." << std::endl;
        }
        else
        {
            std::cout << "Sending batch list to:" << batch_api_endpoint << "" << std::endl;
            CHECK(sendData(data_string, batch_api_endpoint, isverbose) == 1);
        }
    }
    else if (!strcmp(arg_mode.c_str(), "cartp"))
    {
        std::cout << "***cartp mode***" << std::endl;
        std::string tp_family = "cartp";
        if (isverbose)
            std::cout << "***Start build transaction***" << std::endl;
        if (!strcmp(arg_command.c_str(), "") || !strcmp(arg_owner_pic.c_str(), "") || !strcmp(arg_owner.c_str(), ""))
        {
            std::cout << "ERROR: owner, owner_pic and cmd is required." << std::endl;
            exit(0);
        }
        //arg_key = PUBLIC_KEY;
        if (isverbose)
            std::cout << "Setting transaction payload..." << std::endl;
        json payload;
        payload["tnx_cmd"] = arg_command;
        payload["car_id"] = publicKey_str;
        payload["owner"] = arg_owner;

        //load file to Uchar then transform to hex
        std::ifstream infile(arg_owner_pic, std::ios::binary);
        // std::ostringstream ostrm;
        // ostrm << infile.rdbuf();
        std::string picture_content((std::istreambuf_iterator<char>(infile)),
                                    (std::istreambuf_iterator<char>()));

        // payload["owner_picture"] = UcharToHexStr((unsigned char *)ostrm.str().c_str(), ostrm.str().length());
        //payload["owner_picture"] = UcharToHexStr((unsigned char *)picture_content.c_str(), picture_content.length());
        payload["owner_picture"] = UcharToHexStr((unsigned char *)picture_content.c_str(), picture_content.length());
        payload["owner_picture_ext"] = arg_owner_pic.substr(arg_owner_pic.find_last_of(".") + 1); //".png";

        if (isverbose)
            std::cout << "Encoding transaction payload..." << std::endl;
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
        buildAddress(tp_family, payload["car_id"], address);
        const std::string address_str = UcharToHexStr(address, 35);
        if (isverbose)
            std::cout << "address used:" << address_str << std::endl;

        // buildAddress(tp_family, "name", address);
        // address_str = UcharToHexStr(address, 35);
        // std::cout << "address_str:" << address_str << std::endl;

        //tool to convert into json and print the transaction proto:
        google::protobuf::util::JsonPrintOptions json_options;
        json_options.add_whitespace = true;
        json_options.always_print_primitive_fields = true;
        json_options.always_print_enums_as_ints = true;
        json_options.preserve_proto_field_names = true;

        //first build transaction
        //& add all necessary data to protos messages
        if (isverbose)
            std::cout << "Setting transaction header..." << std::endl;
        myTransactionHeader.Clear();
        myTransactionHeader.set_batcher_public_key(publicKey_str); //set batcher pubkey
        myTransactionHeader.set_signer_public_key(publicKey_str);  //set signer pubkey
        myTransactionHeader.set_family_name(tp_family);            //the transaction familly to use
        myTransactionHeader.set_family_version("1.0");             //familly version
        myTransactionHeader.set_payload_sha512(message_hash_str);  //set a hash sha512 of the payload
        myTransactionHeader.add_inputs(address_str);               //1cf126cc488cca4cc3565a876f6040f8b73a7b92475be1d0b1bc453f6140fba7183b9a
        myTransactionHeader.add_outputs(address_str);
        myTransactionHeader.set_nonce(TxnNonce); //set nonce of the transaction
        //done transaction header
        myTransaction->Clear();
        if (isverbose)
            std::cout << "Setting transaction..." << std::endl;
        myTransaction->set_payload(payload_str);
        myTransaction->set_header(myTransactionHeader.SerializePartialAsString());               //build a string of the transaction header
        std::string myTransactionHeader_string = myTransactionHeader.SerializePartialAsString(); //serialize batch header to string

        if (isverbose)
            std::cout << "Signing transaction header..." << std::endl;
        message_hash_str = sha256Data(myTransactionHeader_string);
        HexStrToUchar(message_hash_char, message_hash_str.c_str(), (size_t)HASH_SHA256_SIZE);
        CHECK(SECP256K1_API::secp256k1_ecdsa_sign(ctx, &signature, message_hash_char, privateKey, NULL, NULL) == 1); //make signature
        CHECK(SECP256K1_API::secp256k1_ecdsa_signature_serialize_compact(ctx, signature_serilized, &signature) == 1);
        signature_serilized_str = UcharToHexStr(signature_serilized, SIGNATURE_SERILIZED_SIZE);
        myTransaction->set_header_signature(signature_serilized_str); //set header signature

        //done transaction

        //add transaction to batch header
        if (isverbose)
            std::cout << "Setting batch header..." << std::endl;
        myBatchHeader.add_transaction_ids(signature_serilized_str); //add transaction to batch

        //build batch
        myBatchHeader.set_signer_public_key(publicKey_str); //set batch public key
        //myBatchHeader.SerializeToOstream()
        std::string myBatchHeader_string = myBatchHeader.SerializePartialAsString(); //serialize batch header to string
        if (isverbose)
            std::cout << "Setting batch..." << std::endl;
        myBatch->set_header(myBatchHeader_string); //set header

        if (isverbose)
            std::cout << "Signing batch header..." << std::endl;
        message_hash_str = sha256Data(myBatchHeader_string);
        HexStrToUchar(message_hash_char, message_hash_str.c_str(), (size_t)HASH_SHA256_SIZE);
        CHECK(SECP256K1_API::secp256k1_ecdsa_sign(ctx, &signature, message_hash_char, privateKey, NULL, NULL) == 1); //make signature
        CHECK(SECP256K1_API::secp256k1_ecdsa_signature_serialize_compact(ctx, signature_serilized, &signature) == 1);
        signature_serilized_str = UcharToHexStr(signature_serilized, SIGNATURE_SERILIZED_SIZE);

        myBatch->set_header_signature(signature_serilized_str);
        //myBatch->set_trace(true);//more logs in sawtooth

        // std::cout << "myTransactionHeader" << std::endl;
        // printProtoJson(myTransactionHeader);
        // std::cout << "myTransaction" << std::endl;
        // printProtoJson(*myTransaction);
        // std::cout << "myBatchHeader" << std::endl;
        // printProtoJson(myBatchHeader);
        // std::cout << "myBatch" << std::endl;
        // printProtoJson(*myBatch);

        if (isverbose)
            std::cout << "***Done build real transaction***" << std::endl;

        //send transaction
        std::string data_string = myBatchList.SerializePartialAsString();
        if (!strcmp(batch_api_endpoint.c_str(), ""))
        {
            std::cout << "WARNING: url is required to send the transaction." << std::endl;
        }
        else
        {
            std::cout << "Sending batch list to:" << batch_api_endpoint << "" << std::endl;
            CHECK(sendData(data_string, batch_api_endpoint, isverbose) == 1);
        }
    }
    else if (!strcmp(arg_mode.c_str(), "eth"))
    {
        std::cout << "***ethereum mode***" << std::endl;
        // if (isverbose)
        //     std::cout << "***Start build transaction***" << std::endl;

        //- Create eth account
        //- build sol contract, compile
        //- deploy contract
        //- call contract
        //- use transaction id

        if (!strcmp(eth_mode.c_str(), "create_account"))
        {
            std::cout << "***create account***" << std::endl;

            if (!strcmp(eth_create_account_alias.c_str(), ""))
            {
                std::cout << "ERROR: to create an account you need to give an alias" << std::endl;
            }
            else
            {
                eth_create_account_alias = "luc";

                SethTransaction mySethTransaction;
                mySethTransaction.set_transaction_type(SethTransaction_TransactionType_CREATE_EXTERNAL_ACCOUNT);
                CreateExternalAccountTxn myExternalAccount = mySethTransaction.create_external_account();
                myExternalAccount.set_to("");

                //newAcctAddr
                std::string EvmAddr = "";
            }
        }
        else if (!strcmp(arg_mode.c_str(), "other eth mode"))
        {
        }
    }
    else if (!strcmp(arg_mode.c_str(), "genkeys"))
    {
        std::cout << "***Generating keys***" << std::endl;
        GenerateKeyPair(ctx, privateKey, privateKey_str, publicKey, publicKey_serilized, publicKey_str, isverbose);
        std::cout << std::left;
        std::cout << std::setw(15) << "Private Key: " << privateKey_str << std::endl;
        std::cout << std::setw(15) << "Public Key: " << publicKey_str << std::endl;
    }
    else
    {
        std::cout << "Unknown mode. Only: 'test' or 'eth'" << std::endl;
        exit(1);
    }
    std::cout << "Done." << std::endl;
    return 0;
}
