#!/bin/bash

######
#tnx keys=driver keys
#batch keys=car keys
#
######

tnxprivatekey=$(<tests_keys/driver.priv)
tnxpublickey=$(<tests_keys/driver.pub)
batchprivatekey=$(<tests_keys/car.priv)
batchpublickey=$(<tests_keys/car.pub)

./transaction -v --mode cartp \
    --tnxprivatekey $tnxprivatekey \
    --tnxpublickey $tnxpublickey \
    --batchprivatekey $batchprivatekey \
    --batchpublickey $batchpublickey \
    --cmd crash \
    --date_of_the_accident "$(date +%D)" \
    --hour "$(date +%T)" \
    --location_country "France" \
    --location_place "Valrose" \
    --odometer "52133" \
    --radar_front "230" \
    --radar_back "130" \
    --radar_right "0" \
    --radar_left "300" \
    --collision_front "0" \
    --collision_back "0" \
    --collision_right "1" \
    --collision_left "0" \
    --picture_front "tests_crash/front.jpg" \
    --picture_back "tests_crash/back.jpg" \
    --picture_right "tests_crash/right.jpg" \
    --picture_left "tests_crash/left.jpg" \
    --url http://134.59.230.101:8008/batches