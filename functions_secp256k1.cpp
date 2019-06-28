
#include "functions_secp256k1.h"
#include "base64/base64.h"

#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <string>

#include "cryptopp/cryptlib.h"
#include "cryptopp/osrng.h"
using CryptoPP::AutoSeededRandomPool;
// #include "cryptopp/base64.h"
// #include "cryptopp/queue.h"
// #include "cryptopp/hex.h"
// #include "cryptopp/aes.h"
// #include "cryptopp/integer.h"
// #include "cryptopp/sha.h"
// #include "cryptopp/filters.h"
// #include "cryptopp/files.h"
// #include "cryptopp/eccrypto.h"
// #include "cryptopp/oids.h"
// #include "cryptopp/pubkey.h"
// #include "cryptopp/rng.h"
// #include "cryptopp/mersenne.h"
#include <secp256k1.h>

#include "cbor-cpp/src/cbor.h"
#include "cbor-cpp/src/output_dynamic.h"
#include "cbor-cpp/src/encoder.h"

#include "google/protobuf/util/json_util.h"
#include "protos_pb_h/transaction.pb.h"
#include "protos_pb_h/batch.pb.h"

#include "nlohmann/json.hpp"
using json = nlohmann::json;

