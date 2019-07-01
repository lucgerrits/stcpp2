
# Sawtooth Transaction C++ (STCPP)

This program purpuse is to build transactions for Sawtooth and send them to an existing Sawtooth network.
Note: Use `git submodule update --init --recursive` to pull submodules.

## Install required software

Required:
  * git
  * curl
  * autoconf
  * automake
  * libtool
  * make
  * g++
  * unzip
```
$ sudo apt-get install git curl autoconf automake libtool curl make g++ unzip
```

Install Protobuf:
```
$ #git clone https://github.com/protocolbuffers/protobuf.git
$ cd protobuf
$ git submodule update --init --recursive
$ ./autogen.sh
$ ./configure
$ make
$ make check
$ sudo make install
```

Build STCPP:
```
$ make
$ #test if programme works fine:
$ ./transactionTest test

$ #send transaction
$ ./sendTransaction.sh
```

Clean STCPP:
```
$ make clean
```