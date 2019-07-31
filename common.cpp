#include <iostream>
#include <iomanip>
#include <string>
#include <sstream>
#include <curl/curl.h>

#include "common.h"

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
void buildIntkeyAddress(std::string txnFamily, std::string entryName, unsigned char *ouput35bytes)
{
    //this address is used for intkey transaction processor
    // Example: txnFamily="intkey", entryName="name"
    //Doc: https://sawtooth.hyperledger.org/docs/core/releases/latest/app_developers_guide/address_and_namespace.html#address-components
    emptyBytes(ouput35bytes, 35);
    //build prefix namespace: first set the first 3 bytes
    std::string txnFamily_hex_str = sha512Data(txnFamily);
    unsigned char txnFamily_hex_char[6];
    HexStrToUchar(txnFamily_hex_char, txnFamily_hex_str.c_str(), 6);
    for (int i = 0; i < 3; i++)
    {
        ouput35bytes[i] = txnFamily_hex_char[i];
    }
    //now add the rest of the address: for intkey it is the 32bytes of the LSB of the sha512 of the key
    std::string entryName_hex_str = sha512Data(entryName);
    entryName_hex_str = entryName_hex_str.substr(entryName_hex_str.size() - 64, entryName_hex_str.size());
    unsigned char entryName_hex_char[64];
    HexStrToUchar(entryName_hex_char, entryName_hex_str.c_str(), 64);
    for (int i = 0; i < 32; i++)
    {
        ouput35bytes[3 + i] = entryName_hex_char[i];
    }
    //std::cout << "Address:" << UcharToHexStr(ouput35bytes, 35) << std::endl;
}

void buildCarTPAddress(std::string txnFamily, std::string data_type, std::string key_id, unsigned char *ouput35bytes)
{
    std::cout << "txnFamily:" << txnFamily << std::endl;
    std::cout << "data_type:" << data_type << std::endl;
    std::cout << "key_id:" << key_id << std::endl;
    emptyBytes(ouput35bytes, 35);
    //build prefix namespace: first set the first 3 bytes
    std::string txnFamily_hex_str = sha512Data(txnFamily);
    unsigned char txnFamily_hex_char[6];
    HexStrToUchar(txnFamily_hex_char, txnFamily_hex_str.c_str(), 6);
    for (int i = 0; i < 3; i++)
    {
        ouput35bytes[i] = txnFamily_hex_char[i];
    }
    //next is data_type: 2 bytes
    std::string data_type_hex_str = sha512Data(data_type);
    unsigned char data_type_hex_char[4];
    HexStrToUchar(data_type_hex_char, data_type_hex_str.c_str(), 4);
    for (int i = 0; i < 2; i++)
    {
        ouput35bytes[3 + i] = data_type_hex_char[i];
    }
    //now add the rest of the address: for cartp it is the 30bytes of the MSB of the sha512 of the key
    std::string key_id_hex_str = sha512Data(key_id);
    std::cout << "key_id_hex_str:" << key_id_hex_str << std::endl;
    key_id_hex_str = key_id_hex_str.substr(0, 60);
    unsigned char key_id_hex_char[60];
    HexStrToUchar(key_id_hex_char, key_id_hex_str.c_str(), 60);
    for (int i = 0; i < 30; i++)
    {
        ouput35bytes[5 + i] = key_id_hex_char[i];
    }
    //std::cout << "Address:" << UcharToHexStr(ouput35bytes, 35) << std::endl;
}

static size_t WriteCallback(void *contents, size_t size, size_t nmemb, void *userp)
{
    ((std::string *)userp)->append((char *)contents, size * nmemb);
    return size * nmemb;
}

struct WriteThis
{
    const char *readptr;
    size_t sizeleft;
};
static size_t read_callback(void *dest, size_t size, size_t nmemb, void *userp)
{
    struct WriteThis *wt = (struct WriteThis *)userp;
    size_t buffer_size = size * nmemb;

    if (wt->sizeleft)
    {
        /* copy as much as possible from the source to the destination */
        size_t copy_this_much = wt->sizeleft;
        if (copy_this_much > buffer_size)
            copy_this_much = buffer_size;
        memcpy(dest, wt->readptr, copy_this_much);

        wt->readptr += copy_this_much;
        wt->sizeleft -= copy_this_much;
        return copy_this_much; /* we copied this many bytes */
    }

    return 0; /* no more data left to deliver */
}
int sendData(std::string data, std::string api_endpoint, bool isverbose /*=false*/)
{
    CURL *curl;
    CURLcode res;

    struct WriteThis wt;

    wt.readptr = data.c_str();
    wt.sizeleft = data.length();

    std::cout << "Length data:" << (long)wt.sizeleft << std::endl;

    struct curl_slist *headers = NULL;
    std::string readBuffer;
    curl = curl_easy_init();
    if (curl)
    {

        curl_easy_setopt(curl, CURLOPT_URL, api_endpoint.c_str());
        headers = curl_slist_append(headers, "Content-Type: application/octet-stream");
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);

        curl_easy_setopt(curl, CURLOPT_POST, 1L);
        curl_easy_setopt(curl, CURLOPT_READFUNCTION, read_callback);
        curl_easy_setopt(curl, CURLOPT_READDATA, &wt);

        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE, (long)wt.sizeleft);

        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);

        if (isverbose)
            curl_easy_setopt(curl, CURLOPT_VERBOSE, 1L);
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);

        if (isverbose)
            std::cout << "***Transaction sended***" << std::endl;
        if (isverbose)
            std::cout << "STATUS CODE:" << res << std::endl;
        std::cout << "Response:" << std::endl;
        std::cout << readBuffer << std::endl;
    }
    curl_global_cleanup();
    if (res != CURLE_OK)
        return 0;
    else
        return 1;
}

int LoadKeys(
    SECP256K1_API::secp256k1_context *ctx,
    unsigned char *privateKey,
    std::string &privateKey_str,
    SECP256K1_API::secp256k1_pubkey &publicKey,
    unsigned char *publicKey_serilized,
    std::string &publicKey_str,
    bool isverbose /*=false*/)
{
    if (publicKey_str.length() > 0 && privateKey_str.length() > 0)
    {
        //std::cout << "Using default private and public keys." << std::endl;
        /* LOAD public keys */
        {
            unsigned char pubkey_char[PUBLIC_KEY_SERILIZED_SIZE];
            HexStrToUchar(pubkey_char, publicKey_str.c_str(), (size_t)PUBLIC_KEY_SERILIZED_SIZE);
            if (isverbose)
                std::cout << "Parse Public key:" << UcharToHexStr(pubkey_char, PUBLIC_KEY_SERILIZED_SIZE) << std::endl;
            CHECK(SECP256K1_API::secp256k1_ec_pubkey_parse(ctx, &publicKey, pubkey_char, PUBLIC_KEY_SERILIZED_SIZE) == 1);
            if (isverbose)
                std::cout << "Ok." << std::endl;
        }
        /* LOAD private keys */
        {
            HexStrToUchar(privateKey, privateKey_str.c_str(), (size_t)PRIVATE_KEY_SIZE);
            if (isverbose)
                std::cout << "Parse private key:" << UcharToHexStr(privateKey, PRIVATE_KEY_SIZE) << std::endl;
            CHECK(SECP256K1_API::secp256k1_ec_seckey_verify(ctx, privateKey) == 1);
            if (isverbose)
                std::cout << "Ok." << std::endl;
        }
        return 1;
    }
    else
    {
        std::cerr << "ERROR: No keys loaded. Please verify that you have given keys." << std::endl;
        return 0;
    }
}

int GenerateKeyPair(
    SECP256K1_API::secp256k1_context *ctx,
    unsigned char *privateKey,
    std::string &privateKey_str,
    SECP256K1_API::secp256k1_pubkey &publicKey,
    unsigned char *publicKey_serilized,
    std::string &publicKey_str,
    bool isverbose /*=false*/)
{
    /* Generate a random key */
    {
        emptyBytes(privateKey, PRIVATE_KEY_SIZE);
        generateRandomBytes(privateKey, PRIVATE_KEY_SIZE);
        privateKey_str = UcharToHexStr(privateKey, PRIVATE_KEY_SIZE);
        if (isverbose)
            if (isverbose)
                std::cout << "generatePrivateKey: " << privateKey_str << std::endl;
        while (SECP256K1_API::secp256k1_ec_seckey_verify(ctx, privateKey) == 0) //regenerate private key until it is valid
        {
            generateRandomBytes(privateKey, PRIVATE_KEY_SIZE);
            privateKey_str = UcharToHexStr(privateKey, PRIVATE_KEY_SIZE);
            std::cout << "generatePrivateKey: " << privateKey_str << std::endl;
        }
        CHECK(SECP256K1_API::secp256k1_ec_seckey_verify(ctx, privateKey) == 1);
        if (isverbose)
            std::cout << "Private key verified.\n->Using:" << privateKey_str << std::endl;
    }

    /* Generate a public key */
    {
        emptyBytes(publicKey.data, PUBLIC_KEY_SIZE);
        //FAILING:Segmentation fault
        CHECK(SECP256K1_API::secp256k1_ec_pubkey_create(ctx, &publicKey, privateKey) == 1);
        if (isverbose)
            std::cout << "Public key verified." << std::endl;
        if (isverbose)
            std::cout << "->Using:" << UcharToHexStr(publicKey.data, PUBLIC_KEY_SIZE) << std::endl;
    }

    /* Serilize public key */
    {
        emptyBytes(publicKey_serilized, PUBLIC_KEY_SERILIZED_SIZE);
        size_t pub_key_ser_size = PUBLIC_KEY_SERILIZED_SIZE;
        CHECK(SECP256K1_API::secp256k1_ec_pubkey_serialize(ctx, publicKey_serilized, &pub_key_ser_size, &publicKey, SECP256K1_EC_COMPRESSED) == 1);
        publicKey_str = UcharToHexStr(publicKey_serilized, PUBLIC_KEY_SERILIZED_SIZE);
        if (isverbose)
            std::cout << "Public key serilized ok." << std::endl;
        if (isverbose)
            std::cout << "->Using:" << publicKey_str << std::endl;
    }
    return 1;
}

void printProtoJson(google::protobuf::Message &message)
{
    //tool to convert into json and print the transaction proto:
    google::protobuf::util::JsonPrintOptions proto_json_options;
    proto_json_options.add_whitespace = true;
    proto_json_options.always_print_primitive_fields = true;
    proto_json_options.always_print_enums_as_ints = true;
    proto_json_options.preserve_proto_field_names = true;
    std::string message_json = "";
    google::protobuf::util::MessageToJsonString(message, &message_json, proto_json_options);
    std::cerr << std::endl
              << "Message:"
              << message_json << std::endl;
}
