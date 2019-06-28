
#include "myconversions.h"
#include "base64/base64.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <string>

#include "cryptopp/cryptlib.h"
#include "cryptopp/hex.h"
using CryptoPP::HexDecoder;
using CryptoPP::HexEncoder;
#include "cryptopp/sha.h"
using CryptoPP::SHA256;
#include "cryptopp/filters.h"
using CryptoPP::ArraySink;
using CryptoPP::ArraySource;
using CryptoPP::HashFilter;
using CryptoPP::Redirector;
using CryptoPP::StringSink;
using CryptoPP::StringSource;
#include "cryptopp/files.h"
using CryptoPP::FileSink;
using CryptoPP::FileSource;
#include "cryptopp/eccrypto.h"
using CryptoPP::DEREncodeBitString;
using CryptoPP::DL_GroupParameters_EC;
using CryptoPP::ECDSA;
using CryptoPP::ECP;

#include "cbor-cpp/src/cbor.h"
#include "cbor-cpp/src/output_dynamic.h"
#include "cbor-cpp/src/encoder.h"

//https://stackoverflow.com/a/27173017
void MYCONVFUNC::myconversions::print_bytes(std::ostream &out, const char *title, const unsigned char *data, size_t dataLen, bool format = true)
{
	out << title << std::endl;
	out << std::setfill('0');
	for (size_t i = 0; i < dataLen; ++i)
	{
		out << std::hex << std::setw(2) << (int)data[i];
		if (format)
		{
			out << (((i + 1) % 16 == 0) ? "\n" : " ");
		}
	}
	out << std::endl;
}
//https://stackoverflow.com/a/14051107/11697589
std::string MYCONVFUNC::myconversions::hexStr(byte *data, int len) //bytes to string
{
	std::stringstream ss;
	ss << std::hex;
	for (int i(0); i < len; ++i)
		ss << (int)data[i];
	return ss.str();
}
//http://www.cplusplus.com/forum/general/53397/
int MYCONVFUNC::myconversions::chhex(char ch)
{
	if (isdigit(ch))
		return ch - '0';
	if (tolower(ch) >= 'a' && tolower(ch) <= 'f')
		return ch - 'a' + 10;
	return -1;
}
void MYCONVFUNC::myconversions::hexstrToUchar(unsigned char *dest, const char *source, int bytes_n)
{
	for (bytes_n--; bytes_n >= 0; bytes_n--)
		dest[bytes_n] = 16 * chhex(source[bytes_n * 2]) + chhex(source[bytes_n * 2 + 1]);
}
std::string MYCONVFUNC::myconversions::stringToHex(const std::string signature)
{
	std::string signature_hex;
	StringSource ss2(signature, true /*pumpAll*/, new HexEncoder(new StringSink(signature_hex), false));
	return signature_hex;
}
void MYCONVFUNC::myconversions::encodePayload(const std::string payload, std::string &payload_encoded)
{
	//cbor encode
	// unsigned char *buffer = NULL;
	// cbor::output_dynamic output;
	// cbor::encoder encoder(output);
	// encoder.write_string(payload);
	// buffer = output.data();
	// std::string encodedData = base64_encode(reinterpret_cast<const unsigned char *>(buffer), output.size());
	// payload_encoded = encodedData;

	//base64 encode
	payload_encoded = base64_encode(reinterpret_cast<const unsigned char *>(payload.c_str()), payload.length());
}

void MYCONVFUNC::myconversions::decodePayload(const std::string payload_encoded, std::string &payload_decoded)
{
	//cbor decode
	// std::string decodedData = base64_decode(payload_encoded);
	// cbor::output_dynamic output;
	// cbor::encoder encoder(output);
	// encoder.write_string(decodedData);

	// cbor::input input(output.data(), output.size());
	// cbor::listener_debug listener;
	// cbor::decoder decoder(input, listener);
	// decoder.run();

	//base64 decode
	payload_decoded = base64_decode(payload_encoded);
}

std::string MYCONVFUNC::myconversions::hashData(std::vector<std::uint8_t> payload)
{
	/////////////////////////////////////////////
	//Create a SHA-512 Payload Hash
	std::string digest_hex;
	HexEncoder encoder(new StringSink(digest_hex), false);
	std::string digest;

	SHA256 hash;
	hash.Update(payload.data(), payload.size());
	digest.resize(hash.DigestSize());
	hash.Final((byte *)&digest[0]);
	StringSource ss(digest, true, new Redirector(encoder));
	return digest_hex;
}
void MYCONVFUNC::myconversions::cbor_encode(std::string data, unsigned char *data_out, size_t &data_out_len)
{
	cbor::output_dynamic output;
	cbor::encoder encoder(output);
	encoder.write_string(data);
	data_out = output.data();
	data_out_len = output.size();
}
std::string MYCONVFUNC::myconversions::vector_to_string(std::vector<std::uint8_t> data)
{
	std::string str(data.begin(), data.end());
	return str;
}