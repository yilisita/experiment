#!/bin/bash
# Used to evaluate paillier encryption schema performance in fabric
function compute() {
    index=$1
    echo "Current Progress: $1/40"
    echo $1	
    peer chaincode query -C mychannel -n experiment -c "{\"Args\":[\"EncryptData\", \"$1\"]}"
    peer chaincode query -C mychannel -n experiment -c "{\"Args\":[\"GetSum\"]}"
    peer chaincode query -C mychannel -n experiment -c "{\"Args\":[\"DeleteData\"]}"
}
compute 1
~        
for i in {1..40}
do
	compute $i
done

