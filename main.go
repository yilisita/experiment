package main

import (
	"fmt"
	"test-algorithm/chaincode"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

func main() {
	testChaincode, err := contractapi.NewChaincode(&chaincode.PaillierContract{})
	if err != nil {
		fmt.Println("failed to init paillier contract")
		return
	}
	err = testChaincode.Start()
	if err != nil {
		fmt.Println("failed to start paillier contract")
		return
	}
}
