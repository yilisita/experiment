#!/bin/bash
# Used to evaluate ckks encryption schema performance in fabric
function compute() {
    index=$1
    echo "接收到的参数: ${index}"
    echo $1	
    peer chaincode query -C mychannel -n experiment -c "{\"Args\":[\"EncryptDataCKKS\", \"$1\"]}"
    peer chaincode query -C mychannel -n experiment -c "{\"Args\":[\"GetSumCKKS\"]}"
    peer chaincode query -C mychannel -n experiment -c "{\"Args\":[\"DeleteData\"]}"
}
   
for i in {1..40}
do
	compute $i
done
