#!/bin/bash

./transaction -v --mode cartp \
    --privatekey 1f75aee7c1a1bba8f58faa9250bfc5b80b41d5d9c95a407f01bbdec9a0ee2853 \
    --publickey 02ff11143465085cd36771c602719bf0937d96a5464ec0b617db1114959cd71ee8 \
    --carprivatekey a23ca5ba6024806247074fb463491ce7a15598f36a3f8b14961cdd14866624bf \
    --carpublickey 028278af616aceb71a1c139ae9a33141ae3eefbb6a6dfe74f9be2974d56c7b5eea \
    --cmd new_car \
    --car_brand Batmobile \
    --car_type "X9999" \
    --car_licence "X1-102-10V" \
    --url http://134.59.230.101:8008/batches