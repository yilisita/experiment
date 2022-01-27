#!/bin/bash
# Used to evaluate int vec encryption schema performance in fabric
function compute() {
    index=$1
    echo "接收到的参数: ${index}"
    echo $1	
    peer chaincode query -C mychannel -n experiment -c "{\"Args\":[\"EncryptDataIntvec\", \"$1\"]}"
    peer chaincode query -C mychannel -n experiment -c "{\"Args\":[\"GetSumIntvec\"]}"
    peer chaincode query -C mychannel -n experiment -c "{\"Args\":[\"DeleteData\"]}"
}
# do 40 tests        
for i in {1..40}
do
	compute $i
done

