#!/bin/bash

######
#tnx keys=car keys
#batch keys=factory keys
#
######

tnxprivatekey=$(<tests_keys/car.priv)
tnxpublickey=$(<tests_keys/car.pub)
batchprivatekey=$(<tests_keys/factory1.priv)
batchpublickey=$(<tests_keys/factory1.pub)

./transaction -v --mode cartp \
    --tnxprivatekey $tnxprivatekey \
    --tnxpublickey $tnxpublickey \
    --batchprivatekey $batchprivatekey \
    --batchpublickey $batchpublickey \
    --cmd new_car \
    --car_brand Batmobile \
    --car_type "X9999" \
    --car_licence "X1-102-10V" \
    --url http://134.59.230.101:8008/batches