package chaincode

import (
	"encoding/json"
	"fmt"
	"math/big"
	"strconv"
	"test-algorithm/encryption/intvec"
	"test-algorithm/encryption/paillier"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"github.com/ldsec/lattigo/v2/ckks"
	"github.com/ldsec/lattigo/v2/rlwe"
	"github.com/yilisita/goNum"
)

type PaillierContract struct {
	contractapi.Contract
}

// INTVEC ENCRYPTION
var keyBound = 1000
var t = intvec.GetRandomMatrix(1, 1, keyBound)
var s = intvec.GetSecretKey(t)

func encryptIntvec(n float64) []float64 {
	// 类型转换，转换为slice类型
	var dataMatrix = goNum.NewMatrix(1, 1, []float64{n})
	var ciphertext = intvec.Encrypt(t, dataMatrix).Data
	return ciphertext
}

func decryptIntvec(n []float64) float64 {
	// 类型转换
	// 密文是 2 * 1 的矩阵
	var dataMatrix = goNum.NewMatrix(2, 1, n)
	var plaintext = intvec.Decrypt(s, dataMatrix).Data
	return plaintext[0]
}

// PAILLIER ENCRYPTION
var key = paillier.KeyGenPaillier()

func encrypt(n int64) int64 {
	return paillier.Encryption(key, big.NewInt(n)).Int64()
}

func decrypt(n int64) int64 {
	return paillier.Decryption(key, big.NewInt(n)).Int64()
}

// BEGIN:LATTIGO-CKKS INITIALIZATION
var para, _ = ckks.NewParametersFromLiteral(ckks.PN14QP438)

var kgen = ckks.NewKeyGenerator(para)

var sk, pk = kgen.GenKeyPair()

var rlk = kgen.GenRelinearizationKey(sk, 2)

var encoder = ckks.NewEncoder(para)

var encryptor = ckks.NewEncryptor(para, pk)

var decryptor = ckks.NewDecryptor(para, sk)

var evaluator = ckks.NewEvaluator(para, rlwe.EvaluationKey{Rlk: rlk})

// END:LATTIGO-CKKS INITIALIZATION

// 插入一个数据，插入之前对该数据进行加密
func (p *PaillierContract) InsertData(ctx contractapi.TransactionContextInterface, id string, n int64) error {
	fmt.Println(strconv.FormatInt(encrypt(n), 10))
	return ctx.GetStub().PutState(id, []byte(strconv.FormatInt(encrypt(n), 10)))
}

func (p *PaillierContract) InsertDataIntvec(ctx contractapi.TransactionContextInterface, id string, n float64) error {
	var ciphertext = encryptIntvec(n)
	var numberJSON, err = json.Marshal(ciphertext)
	if err != nil {
		return err
	}
	return ctx.GetStub().PutState(id, numberJSON)
}

func (p *PaillierContract) ReadDataIntvec(ctx contractapi.TransactionContextInterface, id string) float64 {
	var numberJSON, err = ctx.GetStub().GetState(id)
	if err != nil {
		fmt.Println(err)
		return -1
	}
	var numberSlice []float64
	err = json.Unmarshal(numberJSON, &numberSlice)
	if err != nil {
		fmt.Println(err)
		return -1
	}
	return decryptIntvec(numberSlice)
}

func (p *PaillierContract) GetSumIntvec(ctx contractapi.TransactionContextInterface) float64 {
	resultsIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		fmt.Println(err)
		return -1
	}
	defer resultsIterator.Close()

	var sum float64
	for resultsIterator.HasNext() {
		var temp, err = resultsIterator.Next()
		if err != nil {
			fmt.Println(err)
			return -1
		}
		var tempDataSlice []float64
		err = json.Unmarshal(temp.Value, &tempDataSlice)
		if err != nil {
			fmt.Println(err)
			return -1
		}
		var tempFloat = decryptIntvec(tempDataSlice)
		sum += tempFloat
	}
	return sum
}

// Insert data encrypted with ckks schema
func (p *PaillierContract) InsertDataCKKS(ctx contractapi.TransactionContextInterface, id string, n float64) error {
	var value = []float64{n}
	// 编码
	var plaintext = encoder.EncodeNew(value, para.MaxLevel(), para.DefaultScale(), para.LogSlots())
	fmt.Println("plaintext:", plaintext)
	var ciphertext = encryptor.EncryptNew(plaintext)
	fmt.Println("ciphertext:", ciphertext)
	var ciphertextJSON, err = json.Marshal(ciphertext)
	if err != nil {
		return err
	}
	err = ctx.GetStub().PutState(id, ciphertextJSON)
	fmt.Println(ciphertextJSON)
	return err
}

// 读取一条记录，这条记录是使用的paillier加密方案
func (p *PaillierContract) ReadData(ctx contractapi.TransactionContextInterface, id string) (int64, error) {
	numberJSON, err := ctx.GetStub().GetState(id)
	if err != nil {
		return -1, err
	}

	var res int64
	err = json.Unmarshal(numberJSON, &res)
	if err != nil {
		return -1, err
	}
	fmt.Println(res)
	return decrypt(res), nil
}

func (p *PaillierContract) ReadDataCKKS(ctx contractapi.TransactionContextInterface, id string) (float64, error) {
	numberJSON, err := ctx.GetStub().GetState(id)
	if err != nil {
		return -1, err
	}

	var res *ckks.Ciphertext
	err = json.Unmarshal(numberJSON, &res)
	if err != nil {
		return -1, err
	}
	fmt.Println(res)
	var decryptedRes = decryptor.DecryptNew(res)
	var decodedRes = encoder.Decode(decryptedRes, para.LogSlots())
	return real(decodedRes[0]), nil
}

// 返回ledger中所有密文的和，并解密结果
func (p *PaillierContract) GetSum(ctx contractapi.TransactionContextInterface) (int64, error) {
	resultIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return -1, err
	}
	defer resultIterator.Close()

	var sum int64
	for resultIterator.HasNext() {
		temp, err := resultIterator.Next()
		if err != nil {
			return -1, err
		}
		var tempInt int64
		err = json.Unmarshal(temp.Value, &tempInt)
		if err != nil {
			return -1, err
		}
		sum += tempInt
	}
	return decrypt(sum), nil
}

func (p *PaillierContract) GetSumCKKS(ctx contractapi.TransactionContextInterface) (float64, error) {
	resultIterator, err := ctx.GetStub().GetStateByRange("", "")
	if err != nil {
		return -1, err
	}
	defer resultIterator.Close()

	var sum *ckks.Ciphertext
	for resultIterator.HasNext() {
		temp, err := resultIterator.Next()
		if err != nil {
			return -1, err
		}
		var tempCipher *ckks.Ciphertext
		err = json.Unmarshal(temp.Value, &tempCipher)
		if err != nil {
			return -1, err
		}
		sum = evaluator.AddNew(sum, tempCipher)
	}
	var decryptedRes = decryptor.DecryptNew(sum)
	var decodedRes = encoder.Decode(decryptedRes, para.LogSlots())
	return real(decodedRes[0]), nil
}

// 删除ledger中指定的ID数据
func (p *PaillierContract) DeleteData(ctx contractapi.TransactionContextInterface, id string) error {
	return ctx.GetStub().DelState(id)
}
