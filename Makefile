
proto_pb_c_files = protos_pb_h/transaction.pb.cc protos_pb_h/batch.pb.cc
#libs = -lprotobuf -lcurl -lsecp256k1 -Lsecp256k1/.libs/

libs = -Lsecp256k1/.libs/ -lsecp256k1
libs += -Lprotobuf/src/.libs/ -lprotobuf
libs += -Lcryptopp -lcryptopp

includes = -I protos_pb_h/ -I nlohmann/ -I . -I secp256k1/includes
#######objects for main prog:
transaction_objects = main.cpp
#transaction_objects += functions_secp256k1.o myconversions.o
transaction_objects += cbor-cpp/src/encoder.o cbor-cpp/src/decoder.o cbor-cpp/src/output_dynamic.o cbor-cpp/src/input.o cbor-cpp/src/listener_debug.o
transaction_objects += base64/base64.o
transaction_objects += cryptopp/cryptlib.o
# transaction_objects += secp256k1/.libs/libsecp256k1.a
#some flags
flag_global = -pg
flag_main = -pg -std=c++11 -pthread
#info about how cryptopp needs to compile:
#https://www.cryptopp.com/wiki/GNUmakefile#Compilers_and_C.2B.2B_Runtimes

#notre program
transaction: protos_pb_h/transaction.pb.h $(transaction_objects)
	g++  $(flag_main) -Wall -DNDEBUG $(proto_pb_c_files) $(transaction_objects) $(libs) $(includes) -o transaction

#nos fonctions
# functions_secp256k1.o: functions_secp256k1.cpp functions_secp256k1.h cryptopp/cryptlib.o
# 	g++ $(flag_global) -c -std=c++11 functions_secp256k1.cpp -o functions_secp256k1.o
# myconversions.o: myconversions.cpp myconversions.h cryptopp/cryptlib.o
# 	g++ $(flag_global) -c -std=c++11 myconversions.cpp -o myconversions.o

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
	mkdir -p protos_pb_h &&  ./protobuf/src/protoc --proto_path=protos --cpp_out=protos_pb_h/ protos/*.proto

libsecp256k1.a: secp256k1/.libs/libsecp256k1.a
		cp secp256k1/.libs/libsecp256k1.a .
		
#cleanup...
clean_rm_cbor = cbor-cpp/src/*.o
clean_rm_base64 = base64/*.o
clean_rm_keys = *.key
clean_rm_protos = protos_pb_h/*
clean_rm_libsecp256k1 = libsecp256k1.a

clean_cryptopp = #;cd cryptopp/ && make clean && cd -
clean_secp256k1 = #;cd secp256k1/ && make clean && cd -
clean_protobuf = #;cd protobuf/ && make clean && cd -
clean:
	rm -r transaction *.out *.o $(clean_rm_libsecp256k1) $(clean_rm_cbor) $(clean_rm_keys) $(clean_rm_protos) $(clean_rm_base64) $(clean_cryptopp) $(clean_secp256k1)
