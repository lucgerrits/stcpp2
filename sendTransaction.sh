#!/bin/bash

echo "Running..."
#echo -e "test" | curl -v --header "Content-Type: application/octet-stream" --raw --data-binary - --request "POST" "https://sawtooth-api.gerrits-luc.com/batches"
./transactionTest | curl --header "Content-Type: application/octet-stream" --raw --data-binary @- --request "POST" "https://sawtooth-api.gerrits-luc.com/batches"

echo ""
echo "Done."
