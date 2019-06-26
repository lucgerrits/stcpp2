/*
Build test transaction (for Sawtooth Hyperledger)
This will later on:
- build pub/priv keys
- make (random) payload
- sign/build transaction based on keys and payload
- send the batch transaction to sawtooth already existing network

TODO: makefile->needs to compile first

--Luc--
*/

/*
LIBs:
apt-cache pkgnames | grep -i crypto++

apt-get install crypto++*
apt-get install libcurl4-openssl-dev
apt-get install libcbor-dev
apt-get install libjsoncpp*

Docs:
https://www.cryptopp.com/wiki/Main_Page
https://buildmedia.readthedocs.org/media/pdf/libcbor/latest/libcbor.pdf

Ref:
https://github.com/hyperledger/sawtooth-sdk-cxx
*/
#include <iostream>
#include <fstream>
#include <iomanip>
#include <stdio.h>
#include "myfunctions.h"
#include "base64/base64.h"
#include <curl/curl.h>
#include <assert.h>
#include <string>
#include <sys/stat.h>
#include "nlohmann/json.hpp"
using json = nlohmann::json;

#define PRIVATEKEY_FILENAME "ec.private.key"
#define PUBLICKEY_FILENAME "ec.public.key"
#define SAWTOOTH_REST_API "https://sawtooth-explore-8090.gerrits-luc.com"
#define URL_PREFIX "https://"
#define URL_PREFIX_LEN 8
#define USE_CHUNKED 1
#define SAWTOOTH_BATCH_MAX_TRANSACTIONS 100

void Usage(bool bExit = false, int exitCode = 1)
{
    std::cout << "Usage" << std::endl;
    std::cout << "intkey_cxx [options] [connet_string]" << std::endl;
    std::cout << "  -h, --help - print this message" << std::endl;

    std::cout << "  more to come..."
              << std::endl;

    if (bExit)
    {
        exit(exitCode);
    }
}
bool TestConnectString(const char *str)
{
    const char *ptr = str;

    if (strncmp(str, URL_PREFIX, URL_PREFIX_LEN))
    {
        return false;
    }

    ptr = str + URL_PREFIX_LEN;

    if (!isdigit(*ptr))
    {
        if (*ptr == ':' || (ptr = strchr(ptr, ':')) == NULL)
        {
            return false;
        }
        ptr++;
    }
    else
    {
        for (int i = 0; i < 4; i++)
        {
            if (!isdigit(*ptr))
            {
                return false;
            }

            ptr++;
            if (isdigit(*ptr))
            {
                ptr++;
                if (isdigit(*ptr))
                {
                    ptr++;
                }
            }

            if (i < 3)
            {
                if (*ptr != '.')
                {
                    return false;
                }
            }
            else
            {
                if (*ptr != ':')
                {
                    return false;
                }
            }
            ptr++;
        }
    }

    for (int i = 0; i < 4; i++)
    {
        if (!isdigit(*ptr))
        {
            if (i == 0)
            {
                return false;
            }
            break;
        }
        ptr++;
    }

    if (*ptr != 0)
    {
        return false;
    }

    return true;
}
void ParseArgs(int argc, char **argv, std::string &connectStr)
{
    for (int i = 1; i < argc; i++)
    {
        const char *arg = argv[i];
        if (!strcmp(arg, "-h") || !strcmp(arg, "--help"))
        {
            Usage(true, 0);
        }
        else
        {
            if (!TestConnectString(arg))
            {
                std::cout << "Connect string is not in format host:port - "
                          << arg << std::endl;
                Usage(true);
            }
            else
            {
                connectStr = arg;
            }
        }
    }
}

int main(int argc, char **argv)
{
    std::string connectString = SAWTOOTH_REST_API;
    ParseArgs(argc, argv, connectString);
    //std::cout << "Start transaction c++ tester \n";
    bool result = false;

    /////////////////////////////////////////////
    //Creating Private and Public Keys
    ECDSA<ECP, SHA256>::PrivateKey privateKey;
    ECDSA<ECP, SHA256>::PublicKey publicKey;

    if (MYFUNC::myfunctions::files_exist(PRIVATEKEY_FILENAME))
    {
        // Load Key
        //std::cout << "File " << PRIVATEKEY_FILENAME << " exist, loading...\n";
        MYFUNC::myfunctions::LoadPrivateKey(PRIVATEKEY_FILENAME, privateKey);
    }
    else
    {
        // Generate Keys
        result = MYFUNC::myfunctions::GeneratePrivateKey(CryptoPP::ASN1::secp256k1(), privateKey);
        assert(true == result);
        if (!result)
        {
            return -1;
        }
        // Save key in PKCS#9 and X.509 format
        MYFUNC::myfunctions::SavePrivateKey(PRIVATEKEY_FILENAME, privateKey);
    }

    if (MYFUNC::myfunctions::files_exist(PUBLICKEY_FILENAME))
    {
        // Load Key
        //std::cout << "File " << PUBLICKEY_FILENAME << " exist, loading...\n";
        MYFUNC::myfunctions::LoadPublicKey(PUBLICKEY_FILENAME, publicKey);
    }
    else
    {
        // Generate Keys
        result = MYFUNC::myfunctions::GeneratePublicKey(privateKey, publicKey);
        assert(true == result);
        if (!result)
        {
            return -2;
        }
        // Save key in PKCS#9 and X.509 format
        MYFUNC::myfunctions::SavePublicKey(PUBLICKEY_FILENAME, publicKey);
    }
    //publicKey.AccessGroupParameters().SetPointCompression(true);

    // Print Domain Parameters and Keys
    // MYFUNC::myfunctions::PrintDomainParameters(publicKey);
    //MYFUNC::myfunctions::PrintPrivateKey(privateKey);
    //MYFUNC::myfunctions::PrintPublicKey(publicKey);

    MYFUNC::myfunctions::PrintPrivateKeyHex(privateKey);
    MYFUNC::myfunctions::PrintPublicKeyHex(publicKey);

    //MYFUNC::myfunctions::PrintPrivateKeyBase64(privateKey);
    //MYFUNC::myfunctions::PrintPublicKeyBase64(publicKey);

    /////////////////////////////////////////////
    //initialize message/payload list
    std::string messages[SAWTOOTH_BATCH_MAX_TRANSACTIONS];
    for (int i = 0; i < SAWTOOTH_BATCH_MAX_TRANSACTIONS; i++)
    {
        messages[i] = "";
    }
    //set the messages:
    std::string message = "";
    message = "{'Verb': 'set','Name': 'foo','Value': 42}";
    messages[0] = message;

    json payload;
    payload["Verb"] = "set";
    payload["Name"] = "foo";
    payload["Value"] = 42;

    // std::cerr << payload.dump(4) << std::endl;

    // std::vector<std::uint8_t> payload_vector = json::to_cbor(payload);
    // std::cerr << payload_vector.data() << std::endl;
    /////////////////////////////////////////////
    //build the batch:
    //std::ostream &batch_string = std::cout;
    result = MYFUNC::myfunctions::buildBatchFromMessages(privateKey, publicKey, payload, &std::cout);
    //std::string batch_string;
    //result = MYFUNC::myfunctions::buildBatchFromMessages(privateKey, publicKey, messages, SAWTOOTH_BATCH_MAX_TRANSACTIONS, batch_string);
    assert(true == result);

    //std::cout << batch_string << std::endl;

    /////////////////////////////////////////////
    //Send the batch to the SAWTOOTH REST API
    //batch need to be in protbuf format
    //sended in a ocet-stream request to the api
    //Doc: https://sawtooth.hyperledger.org/docs/core/releases/latest/rest_api/endpoint_specs.html#post--batches

    std::string batch_api_endpoint = std::string(connectString) + std::string("/blocks");
    // std::cout << "SAWTOOTH API: \n"
    //           << batch_api_endpoint << std::endl;
    // Now send the transaction with curl in command line

    return 0;
}
