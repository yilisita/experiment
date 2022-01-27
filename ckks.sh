function compute(){
    index = $1
    echo "接收到的参数: $index"
    peer chaincode query -C mychannel -n experiment -c \'{"Args":["EncryptDataCKKS", "${index}"]}\'
    peer chaincode query -C mychannel -n experiment -c '{"Args":["GetSumCKKS"]}'
    peer chaincode query -C mychannel -n experiment -c '{"Args":["DeleteData"]}'
}
compute 