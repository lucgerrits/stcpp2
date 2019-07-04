#!/bin/bash

echo "Running..."
#echo -e "test" | curl -v --header "Content-Type: application/octet-stream" --raw --data-binary - --request "POST" "https://sawtooth-api.gerrits-luc.com/batches"
./transaction -k luc -v 1 -c inc | curl --header "Content-Type: application/octet-stream" --raw --data-binary @- --request "POST" "http://10.212.104.144:8021/batches"

echo ""
echo "Done."
