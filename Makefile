
# proto_pb_c_files = protos_pb_h/transaction.pb.cc protos_pb_h/batch.pb.cc
# libs = -lcrypto++ -lprotobuf -lcurl -lsecp256k1 -Lsecp256k1/.libs
# includes = -I protos_pb_h/ -I nlohmann/ -I secp256k1/includes
# Gflag =#-g
# #notre program
# transactionTest: protos_pb_h/transaction.pb.h main.cpp functions_secp256k1.o encoder.o decoder.o output_dynamic.o input.o listener_debug.o base64.o
# 	g++ $(Gflag) -Wall main.cpp $(proto_pb_c_files) $(libs) *.o $(includes) -o transactionTest

# #nos fonctions
# functions_secp256k1.o: functions_secp256k1.cpp functions_secp256k1.h
# 	g++ $(Gflag) -c -std=c++11 functions_secp256k1.cpp -lcrypto++ -o functions_secp256k1.o

# base64.o: base64/base64.cpp base64/base64.h
# 	g++ -c base64/base64.cpp -o base64.o

# #cbor stuff:
# encoder.o: cbor-cpp/src/encoder.cpp cbor-cpp/src/encoder.h
# 	g++ -c cbor-cpp/src/encoder.cpp -I cbor-cpp/src/ -o encoder.o
# decoder.o: cbor-cpp/src/decoder.cpp cbor-cpp/src/decoder.h
# 	g++ -c cbor-cpp/src/decoder.cpp -I cbor-cpp/src/ -o decoder.o
# listener_debug.o: cbor-cpp/src/listener_debug.cpp cbor-cpp/src/listener_debug.h
# 	g++ -c cbor-cpp/src/listener_debug.cpp -I cbor-cpp/src/ -o listener_debug.o
# input.o: cbor-cpp/src/input.cpp cbor-cpp/src/input.h
# 	g++ -c cbor-cpp/src/input.cpp -I cbor-cpp/src/ -o input.o
# output_dynamic.o: cbor-cpp/src/output_dynamic.cpp cbor-cpp/src/output_dynamic.h
# 	g++ -c cbor-cpp/src/output_dynamic.cpp -I cbor-cpp/src/ -o output_dynamic.o

# protos_pb_h/transaction.pb.h: protos/transaction.proto
# 	protoc --proto_path=protos --cpp_out=protos_pb_h/ protos/*

# #cleanup...
# clean:
# 	rm -r *.o transactionTest *.key protos_pb_h/*

proto_pb_c_files = protos_pb_h/transaction.pb.cc protos_pb_h/batch.pb.cc
libs = -lprotobuf -lcurl -lsecp256k1 -Lsecp256k1/.libs/
includes = -I protos_pb_h/ -I nlohmann/ -I . -I secp256k1/includes
#######objects for main prog:
transactionTest_objects = main.cpp
transactionTest_objects += functions_secp256k1.o myconversions.o
transactionTest_objects += cbor-cpp/src/encoder.o cbor-cpp/src/decoder.o cbor-cpp/src/output_dynamic.o cbor-cpp/src/input.o cbor-cpp/src/listener_debug.o
transactionTest_objects += base64/base64.o
transactionTest_objects += cryptopp/cryptlib.o
# transactionTest_objects += secp256k1/.libs/libsecp256k1.a
#some flags
flag_global = -pg
flag_main = 
#info about how cryptopp needs to compile:
#https://www.cryptopp.com/wiki/GNUmakefile#Compilers_and_C.2B.2B_Runtimes

#notre program
transactionTest: protos_pb_h/transaction.pb.h $(transactionTest_objects)
	g++ $(flag_global) $(flag_main) -Wall -DNDEBUG $(proto_pb_c_files) $(transactionTest_objects) $(libs) $(includes) -o transactionTest ./cryptopp/libcryptopp.a

#nos fonctions
functions_secp256k1.o: functions_secp256k1.cpp functions_secp256k1.h cryptopp/cryptlib.o
	g++ $(flag_global) -c -std=c++11 functions_secp256k1.cpp -o functions_secp256k1.o
myconversions.o: myconversions.cpp myconversions.h cryptopp/cryptlib.o
	g++ $(flag_global) -c -std=c++11 myconversions.cpp -o myconversions.o

base64/base64.o: base64/base64.cpp base64/base64.h
	g++ $(flag_global) -c base64/base64.cpp -o base64/base64.o

#cbor stuff:
cbor-cpp/src/encoder.o: cbor-cpp/src/encoder.cpp cbor-cpp/src/encoder.h
	g++ $(flag_global) -c cbor-cpp/src/encoder.cpp -I cbor-cpp/src/ -o cbor-cpp/src/encoder.o
cbor-cpp/src/decoder.o: cbor-cpp/src/decoder.cpp cbor-cpp/src/decoder.h
	g++ $(flag_global) -c cbor-cpp/src/decoder.cpp -I cbor-cpp/src/ -o cbor-cpp/src/decoder.o
cbor-cpp/src/listener_debug.o: cbor-cpp/src/listener_debug.cpp cbor-cpp/src/listener_debug.h
	g++ $(flag_global) -c cbor-cpp/src/listener_debug.cpp -I cbor-cpp/src/ -o cbor-cpp/src/listener_debug.o
cbor-cpp/src/input.o: cbor-cpp/src/input.cpp cbor-cpp/src/input.h
	g++ $(flag_global) -c cbor-cpp/src/input.cpp -I cbor-cpp/src/ -o cbor-cpp/src/input.o
cbor-cpp/src/output_dynamic.o: cbor-cpp/src/output_dynamic.cpp cbor-cpp/src/output_dynamic.h
	g++ $(flag_global) -c cbor-cpp/src/output_dynamic.cpp -I cbor-cpp/src/ -o cbor-cpp/src/output_dynamic.o

protos_pb_h/transaction.pb.h: protos/transaction.proto
	protoc --proto_path=protos --cpp_out=protos_pb_h/ protos/*

cryptopp/cryptlib.o: cryptopp/cryptlib.h cryptopp/cryptlib.cpp
	cd cryptopp && make && cd -

secp256k1/libsecp256k1.a: secp256k1/include/secp256k1.h secp256k1/src/secp256k1.c
	cd secp256k1/ && ./autogen.sh && ./configure && make && cd -

#cleanup...
clean_cbor = cbor-cpp/src/*.o
clean_base64 = base64/*.o
clean_keys = *.key
clean_proto = protos_pb_h/*

clean_cryptopp = && cd cryptopp/ && make clean && cd -
clean_secp256k1 = && cd secp256k1/ && make clean && cd -
clean:
	rm -r transactionTest *.out *.o $(clean_cbor) $(clean_keys) $(clean_proto) $(clean_base64) $(clean_cryptopp) $(clean_secp256k1)