// 该链码只能用于测试，不能集成application
// 测试paillier,ckks,intvec三种加密算法的加密，计算求和性能
// 配合caliper框架进行使用
// 所有数据都存在临时变量当中，不存入fabric的账本中
// 自变量：
//		1.数据量(10, 20, 30, ..., 100)
//		2.数据位数(2, 3, 4, 5)
//		3.加密方案(paillier, ckks, intvec)
// 因变量：交易时延(latency),单位：s
package chaincode

import (
	"crypto/rand"
	"encoding/json"
	"fmt"
	"math/big"
	"test-algorithm/encryption/intvec"

	paillier "github.com/roasbeef/go-go-gadget-paillier"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
	"github.com/ldsec/lattigo/v2/ckks"
	"github.com/ldsec/lattigo/v2/rlwe"
	"github.com/yilisita/goNum"
)

type PaillierContract struct {
	contractapi.Contract
}

// 用于存放数据的临时变量
var paillier_data [][]byte
var ckks_data []*ckks.Ciphertext
var intvec_data [][]float64

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

var intvec_zero_ciphertext = encryptIntvec(0)

// PAILLIER ENCRYPTION
var key, _ = paillier.GenerateKey(rand.Reader, 128)

func encrypt(n int64) []byte {
	var res, err = paillier.Encrypt(&key.PublicKey, big.NewInt(n).Bytes())
	if err != nil {
		return nil
	}
	return res
}

func decrypt(cByte []byte) string {
	var res, err = paillier.Decrypt(key, cByte)
	if err != nil {
		return ""
	}
	return new(big.Int).SetBytes(res).String()
}

func add(xByte, yByte []byte) []byte {
	var resByte = paillier.AddCipher(&key.PublicKey, xByte, yByte)
	return resByte
}

var paillier_zero_ciphertext = encrypt(0)

// BEGIN:LATTIGO-CKKS INITIALIZATION
var para, _ = ckks.NewParametersFromLiteral(ckks.PN14QP438)

var kgen = ckks.NewKeyGenerator(para)

var sk, pk = kgen.GenKeyPair()

var rlk = kgen.GenRelinearizationKey(sk, 2)

var encoder = ckks.NewEncoder(para)

var encryptor = ckks.NewEncryptor(para, pk)

var decryptor = ckks.NewDecryptor(para, sk)

var evaluator = ckks.NewEvaluator(para, rlwe.EvaluationKey{Rlk: rlk})

var ckks_zero_plaintext = encoder.EncodeNew([]float64{0}, para.MaxLevel(), para.DefaultScale(), para.LogSlots())
var ckks_zero_ciphertext = encryptor.EncryptNew(ckks_zero_plaintext)

// END:LATTIGO-CKKS INITIALIZATION

// 插入一个数据，插入之前对该数据进行加密
func (p *PaillierContract) InsertData(ctx contractapi.TransactionContextInterface, id string, n int64) error {
	var ciphertext = encrypt(n)
	paillier_data = append(paillier_data, ciphertext)
	return nil
}

func (p *PaillierContract) InsertDataIntvec(ctx contractapi.TransactionContextInterface, id string, n float64) error {
	var ciphertext = encryptIntvec(n)
	intvec_data = append(intvec_data, ciphertext)
	return nil
}

// Insert data encrypted with ckks schema
func (p *PaillierContract) InsertDataCKKS(ctx contractapi.TransactionContextInterface, id string, n float64) error {
	var value = []float64{n}
	// 编码
	var plaintext = encoder.EncodeNew(value, para.MaxLevel(), para.DefaultScale(), para.LogSlots())
	var ciphertext = encryptor.EncryptNew(plaintext)
	ckks_data = append(ckks_data, ciphertext)
	return nil
}

// 返回ledger中所有密文的和，并解密结果
func (p *PaillierContract) GetSum(ctx contractapi.TransactionContextInterface) (string, error) {
	var sum []byte
	if len(paillier_data) == 0 {
		return "0", nil
	}
	sum = paillier_zero_ciphertext
	for _, v := range paillier_data {
		fmt.Println(decrypt(v))
		sum = add(sum, v)
	}
	return decrypt(sum), nil
}

func (p *PaillierContract) GetSumCKKS(ctx contractapi.TransactionContextInterface) (float64, error) {
	var sum = ckks_zero_ciphertext // 必须先表示出0的密文
	for _, v := range ckks_data {
		sum = evaluator.AddNew(sum, v)
	}
	var decryptedRes = decryptor.DecryptNew(sum)
	var decodedRes = encoder.Decode(decryptedRes, para.LogSlots())
	return real(decodedRes[0]), nil
}

func (p *PaillierContract) GetSumIntvec(ctx contractapi.TransactionContextInterface) float64 {
	var sum = goNum.NewMatrix(2, 1, intvec_zero_ciphertext)
	for _, v := range intvec_data {
		var tempMatrix = goNum.NewMatrix(2, 1, v)
		sum = goNum.AddMatrix(sum, tempMatrix)
	}
	return decryptIntvec(sum.Data)
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

func (p *PaillierContract) DeleteData(ctx contractapi.TransactionContextInterface) error {
	paillier_data = paillier_data[0:0]
	ckks_data = ckks_data[0:0]
	intvec_data = intvec_data[0:0]
	return nil
}
