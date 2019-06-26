
proto_pb_c_files = protos_pb_h/transaction.pb.cc protos_pb_h/batch.pb.cc
libs = -lcrypto++ -lprotobuf -lcurl
includes = -I protos_pb_h/ -I nlohmann/
#notre program
transactionTest: protos_pb_h/transaction.pb.h main.cpp myfunctions.o encoder.o decoder.o output_dynamic.o input.o listener_debug.o base64.o
	g++ -Wall main.cpp $(proto_pb_c_files) $(libs) *.o $(includes) -o transactionTest

#nos fonctions
myfunctions.o: myfunctions.cpp myfunctions.h
	g++ -c -std=c++11 myfunctions.cpp -o myfunctions.o

base64.o: base64/base64.cpp base64/base64.h
	g++ -c base64/base64.cpp -o base64.o

#cbor stuff:
encoder.o: cbor-cpp/src/encoder.cpp cbor-cpp/src/encoder.h
	g++ -c cbor-cpp/src/encoder.cpp -I cbor-cpp/src/ -o encoder.o
decoder.o: cbor-cpp/src/decoder.cpp cbor-cpp/src/decoder.h
	g++ -c cbor-cpp/src/decoder.cpp -I cbor-cpp/src/ -o decoder.o
listener_debug.o: cbor-cpp/src/listener_debug.cpp cbor-cpp/src/listener_debug.h
	g++ -c cbor-cpp/src/listener_debug.cpp -I cbor-cpp/src/ -o listener_debug.o
input.o: cbor-cpp/src/input.cpp cbor-cpp/src/input.h
	g++ -c cbor-cpp/src/input.cpp -I cbor-cpp/src/ -o input.o
output_dynamic.o: cbor-cpp/src/output_dynamic.cpp cbor-cpp/src/output_dynamic.h
	g++ -c cbor-cpp/src/output_dynamic.cpp -I cbor-cpp/src/ -o output_dynamic.o

protos_pb_h/transaction.pb.h: protos/transaction.proto
	protoc --proto_path=protos --cpp_out=protos_pb_h/ protos/*

#cleanup...
clean:
	rm -r *.o transactionTest *.key protos_pb_h/*