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

    std::string arg_date_of_the_accident = "";
    std::string arg_hour = "";
    std::string arg_location_country = "";
    std::string arg_location_place = "";
    std::string arg_odometer = "";
    std::string arg_radar_front = "";
    std::string arg_radar_back = "";
    std::string arg_radar_right = "";
    std::string arg_radar_left = "";
    std::string arg_collision_front = "";
    std::string arg_collision_back = "";
    std::string arg_collision_right = "";
    std::string arg_collision_left = "";
    std::string arg_picture_front = "";
    std::string arg_picture_back = "";
    std::string arg_picture_right = "";
    std::string arg_picture_left = "";

    std::string eth_mode;
    std::string eth_create_account_alias = "";

    std::string tnxprivKey;
    std::string tnxpubKey;
    std::string batchprivKey;
    std::string batchpubKey;
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
            // //
            // ("factoryprivatekey", "Private key to use for the factory", cxxopts::value<std::string>())
            // //
            // ("factorypublickey", "Public key to use for the factory", cxxopts::value<std::string>())
            //
            ("tnxprivatekey", "Private key to use for the transaction", cxxopts::value<std::string>())
            //
            ("tnxpublickey", "Public key to use for the transaction", cxxopts::value<std::string>())
            //
            ("batchprivatekey", "Private key to use for the batch", cxxopts::value<std::string>())
            //
            ("batchpublickey", "Public key to use for the batch", cxxopts::value<std::string>());

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
        options.add_options("Cartp:crash")
            //Cartp
            //cartp new_owner
            ("date_of_the_accident", "Date of crash", cxxopts::value<std::string>())
            //
            ("hour", "Hour of crash", cxxopts::value<std::string>())
            //
            ("location_country", "Country of crash", cxxopts::value<std::string>())
            //
            ("location_place", "Location of crash", cxxopts::value<std::string>())
            //
            ("odometer", "odometer value", cxxopts::value<std::string>())
            //
            ("radar_front", "radar_front value", cxxopts::value<std::string>())
            //
            ("radar_back", "radar_back value", cxxopts::value<std::string>())
            //
            ("radar_right", "radar_right value", cxxopts::value<std::string>())
            //
            ("radar_left", "radar_left value", cxxopts::value<std::string>())
            //
            ("collision_front", "collision_front value", cxxopts::value<std::string>())
            //
            ("collision_back", "collision_back value", cxxopts::value<std::string>())
            //
            ("collision_right", "collision_right value", cxxopts::value<std::string>())
            //
            ("collision_left", "collision_left value", cxxopts::value<std::string>())
            //
            ("picture_front", "picture_front value", cxxopts::value<std::string>())
            //
            ("picture_back", "picture_back value", cxxopts::value<std::string>())
            //
            ("picture_right", "picture_right value", cxxopts::value<std::string>())
            //
            ("picture_left", "picture_left value", cxxopts::value<std::string>())
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
            std::cout << options.help({"", "Inkey", "Cartp:new_car", "Cartp:new_owner", "Cartp:crash", "Other"}) << std::endl;
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
        if (result.count("tnxprivatekey"))
        {
            arg_options.tnxprivKey = result["tnxprivatekey"].as<std::string>();
        }
        if (result.count("tnxpublickey"))
        {
            arg_options.tnxpubKey = result["tnxpublickey"].as<std::string>();
        }
        if (result.count("batchprivatekey"))
        {
            arg_options.batchprivKey = result["batchprivatekey"].as<std::string>();
        }
        if (result.count("batchpublickey"))
        {
            arg_options.batchpubKey = result["batchpublickey"].as<std::string>();
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
        if (result.count("date_of_the_accident"))
        {
            arg_options.arg_date_of_the_accident = result["date_of_the_accident"].as<std::string>();
        }
        if (result.count("hour"))
        {
            arg_options.arg_hour = result["hour"].as<std::string>();
        }
        if (result.count("location_country"))
        {
            arg_options.arg_location_country = result["location_country"].as<std::string>();
        }
        if (result.count("location_place"))
        {
            arg_options.arg_location_place = result["location_place"].as<std::string>();
        }
        if (result.count("odometer"))
        {
            arg_options.arg_odometer = result["odometer"].as<std::string>();
        }
        if (result.count("radar_front"))
        {
            arg_options.arg_radar_front = result["radar_front"].as<std::string>();
        }
        if (result.count("radar_back"))
        {
            arg_options.arg_radar_back = result["radar_back"].as<std::string>();
        }
        if (result.count("radar_right"))
        {
            arg_options.arg_radar_right = result["radar_right"].as<std::string>();
        }
        if (result.count("radar_left"))
        {
            arg_options.arg_radar_left = result["radar_left"].as<std::string>();
        }
        if (result.count("collision_front"))
        {
            arg_options.arg_collision_front = result["collision_front"].as<std::string>();
        }
        if (result.count("collision_back"))
        {
            arg_options.arg_collision_back = result["collision_back"].as<std::string>();
        }
        if (result.count("collision_right"))
        {
            arg_options.arg_collision_right = result["collision_right"].as<std::string>();
        }
        if (result.count("collision_left"))
        {
            arg_options.arg_collision_left = result["collision_left"].as<std::string>();
        }
        if (result.count("picture_front"))
        {
            arg_options.arg_picture_front = result["picture_front"].as<std::string>();
        }
        if (result.count("picture_back"))
        {
            arg_options.arg_picture_back = result["picture_back"].as<std::string>();
        }
        if (result.count("picture_right"))
        {
            arg_options.arg_picture_right = result["picture_right"].as<std::string>();
        }
        if (result.count("picture_left"))
        {
            arg_options.arg_picture_left = result["picture_left"].as<std::string>();
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
    SawtoothKeys TnxKeys;
    SawtoothKeys BatchKeys;
    Arg_Options options;
    parse(argc, argv, options); //parse command line arguments

    std::string message = "";
    std::string message_hash_str = "";
    unsigned char message_hash_char[HASH_SHA256_SIZE];

    SECP256K1_API::secp256k1_ecdsa_signature signature;
    std::string signature_serilized_str = "";
    unsigned char signature_serilized[SIGNATURE_SERILIZED_SIZE];

    //default keys:
    if (!options.tnxprivKey.empty() && !options.tnxpubKey.empty())
    {
        std::cout << "***Transaction keys Given by command line***" << std::endl;
        TnxKeys.privKey = options.tnxprivKey;
        TnxKeys.pubKey = options.tnxpubKey;
    }
    else
    {
        if (options.isverbose)
            std::cout << "***Using transaction default private and public keys***" << std::endl;
    }
    CHECK(LoadKeys(ctx, TnxKeys.privateKey, TnxKeys.privKey, TnxKeys.publicKey, TnxKeys.publicKey_serilized, TnxKeys.pubKey, options.isverbose) == 1);

    //default keys:
    if (!options.batchprivKey.empty() && !options.batchpubKey.empty())
    {
        std::cout << "***Batch keys Given by command line***" << std::endl;
        BatchKeys.privKey = options.batchprivKey;
        BatchKeys.pubKey = options.batchpubKey;
    }
    else
    {
        if (options.isverbose)
            std::cout << "***Using Batch default private and public keys***" << std::endl;
    }
    CHECK(LoadKeys(ctx, BatchKeys.privateKey, BatchKeys.privKey, BatchKeys.publicKey, BatchKeys.publicKey_serilized, BatchKeys.pubKey, options.isverbose) == 1);

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
            CHECK(SECP256K1_API::secp256k1_ecdsa_sign(ctx, &signature, message_hash_char, TnxKeys.privateKey, NULL, NULL) == 1);
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

        unsigned char Transactionnonce[NONCE_SIZE];
        generateRandomBytes(Transactionnonce, NONCE_SIZE);
        std::string TxnNonce = UcharToHexStr(Transactionnonce, NONCE_SIZE);

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
        myTransactionHeader.set_batcher_public_key(BatchKeys.pubKey); //set batcher pubkey
        myTransactionHeader.set_signer_public_key(TnxKeys.pubKey);    //set signer pubkey
        myTransactionHeader.set_family_name(tp_family);               //the transaction familly to use
        myTransactionHeader.set_family_version("1.0");                //familly version
        myTransactionHeader.set_payload_sha512(message_hash_str);     //set a hash sha512 of the payload
        myTransactionHeader.add_inputs(address_str);                  //1cf126cc488cca4cc3565a876f6040f8b73a7b92475be1d0b1bc453f6140fba7183b9a
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
        CHECK(SECP256K1_API::secp256k1_ecdsa_sign(ctx, &signature, message_hash_char, TnxKeys.privateKey, NULL, NULL) == 1); //make signature
        CHECK(SECP256K1_API::secp256k1_ecdsa_signature_serialize_compact(ctx, signature_serilized, &signature) == 1);
        signature_serilized_str = UcharToHexStr(signature_serilized, SIGNATURE_SERILIZED_SIZE);
        myTransaction->set_header_signature(signature_serilized_str); //set header signature

        //done transaction

        //add transaction to batch header
        if (options.isverbose)
            std::cout << "Setting batch header..." << std::endl;
        myBatchHeader.add_transaction_ids(signature_serilized_str); //add transaction to batch

        //build batch
        myBatchHeader.set_signer_public_key(BatchKeys.pubKey); //set batch public key
        //myBatchHeader.SerializeToOstream()
        std::string myBatchHeader_string = myBatchHeader.SerializePartialAsString(); //serialize batch header to string
        if (options.isverbose)
            std::cout << "Setting batch..." << std::endl;
        myBatch->set_header(myBatchHeader_string); //set header

        if (options.isverbose)
            std::cout << "Signing batch header..." << std::endl;
        message_hash_str = sha256Data(myBatchHeader_string);
        HexStrToUchar(message_hash_char, message_hash_str.c_str(), (size_t)HASH_SHA256_SIZE);
        CHECK(SECP256K1_API::secp256k1_ecdsa_sign(ctx, &signature, message_hash_char, BatchKeys.privateKey, NULL, NULL) == 1); //make signature
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

        int max_nb_addresses = 10;
        int nb_addresses = 0;
        int addresses_io[max_nb_addresses]; //0 is only input, 1 only output, 2 input & output
        unsigned char **addresses = new unsigned char *[max_nb_addresses];
        for (int i = 0; i < max_nb_addresses; ++i)
        {
            addresses[i] = new unsigned char[35];
        }

        json payload;
        //following payload fields are always required
        payload["tnx_cmd"] = options.arg_command;
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
            payload["factory_id"] = BatchKeys.pubKey;
            payload["car_id"] = TnxKeys.pubKey;
            payload["car_brand"] = options.arg_car_brand;
            payload["car_type"] = options.arg_car_type;
            payload["car_licence"] = options.arg_car_licence;

            buildCarTPAddress(tp_family, "car", TnxKeys.pubKey, addresses[nb_addresses]);
            addresses_io[nb_addresses] = 2;
            nb_addresses++;
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
            payload["owner_id"] = TnxKeys.pubKey;
            payload["car_id"] = BatchKeys.pubKey;
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

            buildCarTPAddress(tp_family, "car", BatchKeys.pubKey, addresses[nb_addresses]);
            addresses_io[nb_addresses] = 0;
            nb_addresses++;
            buildCarTPAddress(tp_family, "owner", BatchKeys.pubKey, addresses[nb_addresses]);
            addresses_io[nb_addresses] = 2;
            nb_addresses++;
        }
        else if (!strcmp(options.arg_command.c_str(), "crash"))
        {
            //set payload for the command crash
            if (options.arg_date_of_the_accident.empty() ||
                options.arg_hour.empty() ||
                options.arg_location_country.empty() ||
                options.arg_location_place.empty() ||
                options.arg_odometer.empty() ||
                options.arg_radar_front.empty() ||
                options.arg_radar_back.empty() ||
                options.arg_radar_right.empty() ||
                options.arg_radar_left.empty() ||
                options.arg_collision_front.empty() ||
                options.arg_collision_back.empty() ||
                options.arg_collision_right.empty() ||
                options.arg_collision_left.empty() ||
                options.arg_picture_front.empty() ||
                options.arg_picture_back.empty() ||
                options.arg_picture_right.empty() ||
                options.arg_picture_left.empty())
            {
                std::cout << "ERROR: ";
                std::cout << "date_of_the_accident, ";
                std::cout << "hour, ";
                std::cout << "location_country, ";
                std::cout << "location_place, ";
                std::cout << "odometer, ";
                std::cout << "radar_front, ";
                std::cout << "radar_back, ";
                std::cout << "radar_right, ";
                std::cout << "radar_left, ";
                std::cout << "collision_front, ";
                std::cout << "collision_back, ";
                std::cout << "collision_right, ";
                std::cout << "collision_left, ";
                std::cout << "picture_front, ";
                std::cout << "picture_back, ";
                std::cout << "picture_right, ";
                std::cout << "picture_left, ";
                std::cout << "is required." << std::endl;
                exit(1);
            }
            payload["owner_id"] = TnxKeys.pubKey;
            payload["car_id"] = BatchKeys.pubKey;
            payload["date_of_the_accident"] = options.arg_date_of_the_accident;
            payload["hour"] = options.arg_hour;
            payload["location_country"] = options.arg_location_country;
            payload["location_place"] = options.arg_location_place;
            payload["odometer"] = options.arg_odometer;
            payload["radar_front"] = options.arg_radar_front;
            payload["radar_back"] = options.arg_radar_back;
            payload["radar_right"] = options.arg_radar_right;
            payload["radar_left"] = options.arg_radar_left;
            payload["collision_front"] = options.arg_collision_front;
            payload["collision_back"] = options.arg_collision_back;
            payload["collision_right"] = options.arg_collision_right;
            payload["collision_left"] = options.arg_collision_left;

            {
                //load file to Uchar then transform to hex
                std::ifstream infile(options.arg_picture_front, std::ios::binary);
                std::string picture_content((std::istreambuf_iterator<char>(infile)),
                                            (std::istreambuf_iterator<char>()));
                payload["picture_front"] = UcharToHexStr((unsigned char *)picture_content.c_str(), picture_content.length());
                payload["picture_front_ext"] = options.arg_picture_front.substr(options.arg_picture_front.find_last_of(".") + 1); //".png";
            }
            {
                //load file to Uchar then transform to hex
                std::ifstream infile(options.arg_picture_back, std::ios::binary);
                std::string picture_content((std::istreambuf_iterator<char>(infile)),
                                            (std::istreambuf_iterator<char>()));
                payload["picture_back"] = UcharToHexStr((unsigned char *)picture_content.c_str(), picture_content.length());
                payload["picture_back_ext"] = options.arg_picture_back.substr(options.arg_picture_back.find_last_of(".") + 1); //".png";
            }

            {
                //load file to Uchar then transform to hex
                std::ifstream infile(options.arg_picture_right, std::ios::binary);
                std::string picture_content((std::istreambuf_iterator<char>(infile)),
                                            (std::istreambuf_iterator<char>()));
                payload["picture_right"] = UcharToHexStr((unsigned char *)picture_content.c_str(), picture_content.length());
                payload["picture_right_ext"] = options.arg_picture_right.substr(options.arg_picture_right.find_last_of(".") + 1); //".png";
            }

            {
                //load file to Uchar then transform to hex
                std::ifstream infile(options.arg_picture_left, std::ios::binary);
                std::string picture_content((std::istreambuf_iterator<char>(infile)),
                                            (std::istreambuf_iterator<char>()));
                payload["picture_left"] = UcharToHexStr((unsigned char *)picture_content.c_str(), picture_content.length());
                payload["picture_left_ext"] = options.arg_picture_left.substr(options.arg_picture_left.find_last_of(".") + 1); //".png";
            }

            buildCarTPAddress(tp_family, "car", BatchKeys.pubKey, addresses[nb_addresses]);
            addresses_io[nb_addresses] = 0;
            nb_addresses++;
            buildCarTPAddress(tp_family, "crash", BatchKeys.pubKey, addresses[nb_addresses]);
            addresses_io[nb_addresses] = 2;
            nb_addresses++;
            buildCarTPAddress(tp_family, "owner", BatchKeys.pubKey, addresses[nb_addresses]);
            addresses_io[nb_addresses] = 0;
            nb_addresses++;
            buildCarTPAddress(tp_family, "crash", TnxKeys.pubKey, addresses[nb_addresses]);
            addresses_io[nb_addresses] = 2;
            nb_addresses++;
        }
        else
        {
            std::cout << "ERROR: Command " << options.arg_command << " unknown." << std::endl;
            exit(1);
        }
        if (options.isverbose)
            std::cout << "Address used:" << std::endl;
        std::string addresses_str[max_nb_addresses];
        for (int i = 0; i < nb_addresses; i++)
        {
            addresses_str[i] = UcharToHexStr(addresses[i], 35);
            if (options.isverbose)
                std::cout << "->" << addresses_str[i] << std::endl;
        }
        if (options.isverbose)
            std::cout << "Address for \"factory settings\":" << SETTINGS_CARTP_FACTORY_ADDRESS << std::endl;

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

        unsigned char Transactionnonce[NONCE_SIZE];
        generateRandomBytes(Transactionnonce, NONCE_SIZE);
        std::string TxnNonce = UcharToHexStr(Transactionnonce, NONCE_SIZE);

        message_hash_str = sha512Data(message);

        //first build transaction
        //& add all necessary data to protos messages
        if (options.isverbose)
            std::cout << "Setting transaction header..." << std::endl;
        myTransactionHeader.Clear();
        myTransactionHeader.set_batcher_public_key(BatchKeys.pubKey); //set batcher pubkey
        myTransactionHeader.set_signer_public_key(TnxKeys.pubKey);    //set signer pubkey
        myTransactionHeader.set_family_name(tp_family);               //the transaction familly to use
        myTransactionHeader.set_family_version("1.0");                //familly version
        myTransactionHeader.set_payload_sha512(message_hash_str);     //set a hash sha512 of the payload
        for (int i = 0; i < nb_addresses; i++)
        {
            if (addresses_io[i] == 0) //only input
                myTransactionHeader.add_inputs(addresses_str[i]);
            else if (addresses_io[i] == 1) //only output
                myTransactionHeader.add_outputs(addresses_str[i]);
            else if (addresses_io[i] == 2) //input & ouput
            {
                myTransactionHeader.add_inputs(addresses_str[i]);
                myTransactionHeader.add_outputs(addresses_str[i]);
            }
        }
        myTransactionHeader.add_inputs(SETTINGS_CARTP_FACTORY_ADDRESS); //read access to factory settings
        myTransactionHeader.set_nonce(TxnNonce);                        //set nonce of the transaction
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
        CHECK(SECP256K1_API::secp256k1_ecdsa_sign(ctx, &signature, message_hash_char, TnxKeys.privateKey, NULL, NULL) == 1); //make signature
        CHECK(SECP256K1_API::secp256k1_ecdsa_signature_serialize_compact(ctx, signature_serilized, &signature) == 1);
        signature_serilized_str = UcharToHexStr(signature_serilized, SIGNATURE_SERILIZED_SIZE);
        myTransaction->set_header_signature(signature_serilized_str); //set header signature

        //done transaction

        //add transaction to batch header
        if (options.isverbose)
            std::cout << "Setting batch header..." << std::endl;
        myBatchHeader.add_transaction_ids(signature_serilized_str); //add transaction to batch

        //build batch
        myBatchHeader.set_signer_public_key(BatchKeys.pubKey); //set batch public key
        //myBatchHeader.SerializeToOstream()
        std::string myBatchHeader_string = myBatchHeader.SerializePartialAsString(); //serialize batch header to string
        if (options.isverbose)
            std::cout << "Setting batch..." << std::endl;
        myBatch->set_header(myBatchHeader_string); //set header

        if (options.isverbose)
            std::cout << "Signing batch header..." << std::endl;
        message_hash_str = sha256Data(myBatchHeader_string);
        HexStrToUchar(message_hash_char, message_hash_str.c_str(), (size_t)HASH_SHA256_SIZE);
        CHECK(SECP256K1_API::secp256k1_ecdsa_sign(ctx, &signature, message_hash_char, BatchKeys.privateKey, NULL, NULL) == 1); //make signature
        CHECK(SECP256K1_API::secp256k1_ecdsa_signature_serialize_compact(ctx, signature_serilized, &signature) == 1);
        signature_serilized_str = UcharToHexStr(signature_serilized, SIGNATURE_SERILIZED_SIZE);

        myBatch->set_header_signature(signature_serilized_str);
        //myBatch->set_trace(true); //more logs in sawtooth

        std::cout << "myTransactionHeader" << std::endl;
        printProtoJson(myTransactionHeader);
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

        GenerateKeyPair(ctx, TnxKeys.privateKey, TnxKeys.privKey, TnxKeys.publicKey, TnxKeys.publicKey_serilized, TnxKeys.pubKey, options.isverbose);
        std::cout << std::left;
        std::cout << std::setw(15) << "Private Key: " << TnxKeys.privKey << std::endl;
        std::cout << std::setw(15) << "Public Key: " << TnxKeys.pubKey << std::endl;
    }
    else
    {
        std::cout << "Unknown mode \"" << options.arg_mode << "\" . Only: 'test' or 'eth'" << std::endl;
        exit(1);
    }
    //std::cout << "Done." << std::endl;
    return 0;
}
