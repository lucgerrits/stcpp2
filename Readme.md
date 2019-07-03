
# Sawtooth Transaction C++ (STCPP)

This program purpuse is to build transactions for Sawtooth and send them to an existing Sawtooth network.

Important Note: Pull submodules !!
```
$ git clone https://gogs.gerrits-luc.com/luc/stcpp2.git
$ cd stcpp2/
$ git submodule update --init --recursive
```

### Install required software

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
$ #git submodule update --init --recursive
$ ./autogen.sh
$ ./configure
$ make
$ sudo make install
```

Install Secp256k1:
```
$ cd secp256k1/
$ ./autogen.sh
$ ./configure
$ make
$ sudo make install
```

### Build STCPP:
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


### ERRORS

```
$ ./transaction: error while loading shared libraries: libprotobuf.so.20: cannot open shared object file: No such file or directory
$ sudo ldconfig
```


### configure file

This configure file is used in protobuf. It generates Makefiles that allow the use of *gproof* tools. 