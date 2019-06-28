#include <iostream>
#include <fstream>
#include <iomanip>
#include <string>

typedef unsigned char byte;

#include "nlohmann/json.hpp"
using json = nlohmann::json;

#ifndef MYCONVERSIONS_H // include guard
#define MYCONVERSIONS_H

// myconversions.h
namespace MYCONVFUNC
{
class myconversions
{
public:
  std::string stringToHex(const std::string signature);
  void encodePayload(const std::string payload, std::string &payload_encoded);
  void decodePayload(const std::string payload_encoded, std::string &payload_decoded);
  std::string hashData(std::vector<std::uint8_t> payload);
  void cbor_encode(std::string data, unsigned char *data_out, size_t &data_out_len);
  std::string vector_to_string(std::vector<std::uint8_t> data);
  void hexstrToUchar(unsigned char *dest, const char *source, int bytes_n);
  int chhex(char ch);
  std::string hexStr(byte *data, int len);
  void print_bytes(std::ostream &out, const char *title, const unsigned char *data, size_t dataLen, bool format);

};
} // namespace MYCONVFUNC

#endif /* MYCONVERSIONS_H */