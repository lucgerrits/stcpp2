
proto_pb_c_files = protos_pb_h/transaction.pb.cc protos_pb_h/batch.pb.cc protos_pb_h/seth.pb.cc
libs = -Lprotobuf/.libs/lib -lprotobuf -lcurl -L. -lsecp256k1
includes = -I protos_pb_h/ -I nlohmann/ -I . -I secp256k1/includes -Iprotobuf/.libs/include
#######objects for main prog:
transaction_objects = main.cpp
transaction_objects += cbor-cpp/src/encoder.o cbor-cpp/src/decoder.o cbor-cpp/src/output_dynamic.o cbor-cpp/src/input.o cbor-cpp/src/listener_debug.o
transaction_objects += cryptopp/cryptlib.o
transaction_objects += common.o
#some flags
flag_global = -pg -std=c++11
flag_main = -pthread -std=c++11
#info about how cryptopp needs to compile:
#https://www.cryptopp.com/wiki/GNUmakefile#Compilers_and_C.2B.2B_Runtimes

#notre program
transaction: protos_pb_h/transaction.pb.h $(transaction_objects) libsecp256k1.a
	g++ $(flag_global) $(flag_main) -Wall -DNDEBUG $(proto_pb_c_files) $(transaction_objects) $(libs) $(includes) -o transaction ./cryptopp/libcryptopp.a

common.o: common.cpp common.h
	g++ $(flag_global) $(libs) $(includes) -c common.cpp -o common.o

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
	mkdir -p protos_pb_h &&  protobuf/src/protoc --proto_path=protos --cpp_out=protos_pb_h/ protos/*

cryptopp/cryptlib.o: cryptopp/cryptlib.h cryptopp/cryptlib.cpp
	cd cryptopp && make && cd -

libsecp256k1.a: secp256k1/.libs/libsecp256k1.a
	cp secp256k1/.libs/libsecp256k1.a .

#cleanup...
clean_rm_cbor = cbor-cpp/src/*.o
clean_rm_keys = *.key
clean_rm_protos = protos_pb_h/*
clean_rm_libsecp256k1 = libsecp256k1.a

clean_cryptopp = #;cd cryptopp/ && make clean && cd -
clean_secp256k1 = #;cd secp256k1/ && make clean && cd -
clean_protobuf = #;cd protobuf/ && make clean && cd -
clean:
	rm -r transaction *.out *.o $(clean_rm_libsecp256k1) $(clean_rm_cbor) $(clean_rm_keys) $(clean_rm_protos) $(clean_cryptopp) $(clean_secp256k1)