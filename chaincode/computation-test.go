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
	//"encoding/json"
	"fmt"
	"log"
	"math"
	"math/big"
	"strconv"
	"test-algorithm/encryption/intvec"
	"time"

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
func InsertData(n int64) error {
	var ciphertext = encrypt(n)
	paillier_data = append(paillier_data, ciphertext)
	return nil
}

func InsertDataIntvec(n float64) error {
	var ciphertext = encryptIntvec(n)
	intvec_data = append(intvec_data, ciphertext)
	return nil
}

// Insert data encrypted with ckks schema
func InsertDataCKKS(n float64) error {
	var value = []float64{n}
	// 编码
	var plaintext = encoder.EncodeNew(value, para.MaxLevel(), para.DefaultScale(), para.LogSlots())
	var ciphertext = encryptor.EncryptNew(plaintext) // bug: out of bounds
	ckks_data = append(ckks_data, ciphertext)
	return nil
	//----------------------------------------
}

func (p *PaillierContract) InsertNDataCKKS(ctx contractapi.TransactionContextInterface, times int, n float64) error {
	start := time.Now()
	for i := 0; i < times; i++ {
		err := InsertDataCKKS(n)
		if err != nil {
			return err
		}
	}
	end := time.Since(start).Nanoseconds()
	var avgCost float64 = -0.001
	if times != 0 {
		avgCost = float64(end) / float64(times)
	}

	fmt.Println("明文求和:", float64(times)*n, "加密总用时:", end, "ns", "数据量:", times, "平均加密用时:", avgCost, "ns")
	return nil
}

func (p *PaillierContract) InsertNData(ctx contractapi.TransactionContextInterface, times int, n int64) error {
	start := time.Now()
	for i := 0; i < times; i++ {
		err := InsertData(n)
		if err != nil {
			return err
		}
	}
	end := time.Since(start).Nanoseconds()
	var avgCost float64 = -0.001
	if times != 0 {
		avgCost = float64(end) / float64(times)
	}

	fmt.Println("明文求和:", int64(times)*n, "加密总用时:", end, "ns", "数据量:", times, "平均加密用时:", avgCost, "ns")
	return nil
}

// 一次性向临时变量中增加n个数据，每个数据都是一样的，加密方案：Int vec
//		times：数据量
//      n: 数据
func (p *PaillierContract) InsertNDataIntvec(ctx contractapi.TransactionContextInterface, times int, n float64) error {
	start := time.Now()
	for i := 0; i < times; i++ {
		err := InsertDataIntvec(n)
		if err != nil {
			return err
		}
	}
	end := time.Since(start).Nanoseconds()
	var avgCost float64 = -0.001
	if times != 0 {
		avgCost = float64(end) / float64(times)
	}

	fmt.Println("明文求和:", float64(times)*n, "加密总用时:", end, "ns", "数据量:", times, "平均加密用时:", avgCost, "ns")
	return nil
}

// 返回ledger中所有密文的和，并解密结果
func (p *PaillierContract) GetSum(ctx contractapi.TransactionContextInterface) (string, error) {
	var length = len(paillier_data)
	var sum []byte
	if len(paillier_data) == 0 {
		return "0", nil
	}
	var digit = len(decrypt(paillier_data[0]))
	sum = paillier_zero_ciphertext
	start := time.Now()
	for _, v := range paillier_data {
		//fmt.Println(decrypt(v))
		sum = add(sum, v)
	}
	var res = decrypt(sum)
	end := time.Since(start).Nanoseconds()
	fmt.Println("数据位数:", digit, "数据量:", length, "GetSum用时:", end, "ns", "结果:", res)
	return res, nil
}

func (p *PaillierContract) GetSumCKKS(ctx contractapi.TransactionContextInterface) (float64, error) {
	var length = len(ckks_data)
	var sum = ckks_zero_ciphertext // 必须先表示出0的密文
	start := time.Now()
	for _, v := range ckks_data {
		sum = evaluator.AddNew(sum, v)
	}
	var decryptedRes = decryptor.DecryptNew(sum)
	var decodedRes = encoder.Decode(decryptedRes, para.LogSlots())
	var res = real(decodedRes[0])
	end := time.Since(start).Nanoseconds()
	var digit int
	if len(ckks_data) == 0 {
		digit = 0
	} else {
		var decrypted1st = decryptor.DecryptNew(ckks_data[0])
		var decodedRes = encoder.Decode(decrypted1st, para.LogSlots())
		digit = len(strconv.Itoa(int(math.Floor(real(decodedRes[0])))))
	}
	fmt.Println("数据位数:", digit, "数据量:", length, "GetSumCKKS用时:", end, "ns", "结果:", res)
	return res, nil
}

func (p *PaillierContract) GetSumIntvec(ctx contractapi.TransactionContextInterface) float64 {
	var length = len(intvec_data)
	var sum = goNum.NewMatrix(2, 1, intvec_zero_ciphertext)
	var digit int
	if len(intvec_data) == 0 {
		digit = 0
	} else {
		var res1st = int(decryptIntvec(intvec_data[0]))
		digit = len(strconv.Itoa(res1st))
	}
	start := time.Now()
	for _, v := range intvec_data {
		var tempMatrix = goNum.NewMatrix(2, 1, v)
		sum = goNum.AddMatrix(sum, tempMatrix)
	}
	var res = decryptIntvec(sum.Data)
	end := time.Since(start).Nanoseconds()
	fmt.Println("数据位数", digit, "数据量:", length, "GetSumIntvec用时:", end, "ns", "结果:", res)
	return res
}

func (p *PaillierContract) DeleteData(ctx contractapi.TransactionContextInterface) error {
	log.Printf("删除所有已有数据")
	paillier_data = paillier_data[0:0]
	ckks_data = ckks_data[0:0]
	intvec_data = intvec_data[0:0]
	return nil
}

// EncryptData会根据传入的index，对该index的切片数据使用paillier加密
// 函数执行过程中,打印：数据量，数据位数，加密总共用时，加密平均用时，明文求和
// 将加密好的数据放入临时变量中
func (p *PaillierContract) EncryptData(ctx contractapi.TransactionContextInterface, index int) {
	// 复制一份原始数据，以便可以重复使用
	var srcData = DataIndex[index]
	var copyData = make([]int64, len(srcData))
	copy(copyData, srcData)

	// 明文求和
	var sum int64
	for _, v := range copyData {
		sum += v
	}

	// 加密
	paillier_data = paillier_data[:] // 首先清楚里面已有的数据
	start := time.Now()
	for _, v := range copyData {
		paillier_data = append(paillier_data, encrypt(v))
	}
	end := time.Since(start).Nanoseconds()

	// 数据量
	var length = len(srcData)

	// 数据位数
	var firstEle = srcData[0]
	var digit = len(strconv.Itoa(int(firstEle)))

	// 结果统计
	fmt.Printf("加密方案:paillier 数据量:%v 数据位数:%v 加密总用时:%vns 加密平均用时:%vns 明文求和:%v\n", length, digit, end, float64(end)/float64(length), sum)
}

// EncryptDataCKKS的功能与EncryptData相似，只不过使用的CKKS加密方案
func (p *PaillierContract) EncryptDataCKKS(ctx contractapi.TransactionContextInterface, index int) {
	// 复制原始数据
	var srcData = DataIndex[index]
	var copyData = make([]int64, len(srcData))
	copy(copyData, srcData)
	// 做一个类型转换，因为ckks要求float类型
	var transformedData [][]float64
	// 顺便做个明文求和
	var sum int64
	for _, v := range copyData {
		sum += v
		transformedData = append(transformedData, []float64{float64(v)})
	}

	// 加密
	ckks_data = ckks_data[0:0] // 清楚原有的数据
	start := time.Now()
	for _, v := range transformedData {
		var plaintext = encoder.EncodeNew(v, para.MaxLevel(), para.DefaultScale(), para.LogSlots())
		var ciphertext = encryptor.EncryptNew(plaintext)
		ckks_data = append(ckks_data, ciphertext)
	}
	end := time.Since(start).Nanoseconds()

	// 数据量
	var length = len(srcData)

	// 数据位数
	var firstEle = srcData[0]
	var digit = len(strconv.Itoa(int(firstEle)))

	// 结果统计
	fmt.Printf("加密方案:ckks 数据量:%v 数据位数:%v 加密总用时:%vns 加密平均用时:%vns 明文求和:%v\n", length, digit, end, float64(end)/float64(length), sum)
}

// EncryptDataCKKS的功能与EncryptData相似，只不过使用的CKKS加密方案
func (p *PaillierContract) EncryptDataIntvec(ctx contractapi.TransactionContextInterface, index int) {
	// 复制原始数据
	var srcData = DataIndex[index]
	var copyData = make([]int64, len(srcData))
	copy(copyData, srcData)
	// 做一个类型转换，因为intvec要求float类型
	var transformedData []float64
	// 顺便做个明文求和
	var sum int64
	for _, v := range copyData {
		sum += v
		transformedData = append(transformedData, float64(v))
	}

	// 加密
	intvec_data = intvec_data[0:0] // 清楚原有的数据
	start := time.Now()
	for _, v := range transformedData {
		var ciphertext = encryptIntvec(v)
		intvec_data = append(intvec_data, ciphertext) // 将加密后的数据放进去
	}
	end := time.Since(start).Nanoseconds()

	// 数据量
	var length = len(srcData)

	// 数据位数
	var firstEle = srcData[0]
	var digit = len(strconv.Itoa(int(firstEle)))

	// 结果统计
	fmt.Printf("加密方案:intvec 数据量:%v 数据位数:%v 加密总用时:%vns 加密平均用时:%vns 明文求和:%v\n", length, digit, end, float64(end)/float64(length), sum)
}
