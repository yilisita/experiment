package chaincode

import (
	"fmt"
	"math/big"
	"math/rand"
	"test-algorithm/encryption/paillier"
	"time"

	"github.com/hyperledger/fabric-contract-api-go/contractapi"
)

type PaillierContract struct {
	contractapi.Contract
}

var key = paillier.KeyGenPaillier()

func encrypt(n int64) int64 {
	return paillier.Encryption(key, big.NewInt(n)).Int64()
}

func decrypt(n int64) int64 {
	return paillier.Encryption(key, big.NewInt(n)).Int64()
}

var DATA_POOL []int64
var SUM int64

// 生成待测试的数据
// n: 表示生成多少条数据
// bit: 表示生成的每条数据的位数，e.g. 两位数，三位数
func (p *PaillierContract) GenerateData(ctx contractapi.TransactionContextInterface, n, bit int) {
	// 生成之前先清除数据池中的数据
	DATA_POOL = DATA_POOL[0:0]
	// 在循环体外面播撒种子
	rand.Seed(time.Now().Unix())
	for i := 0; i < n; i++ {
		temp := rand.Int63()
		SUM += temp
		DATA_POOL = append(DATA_POOL, encrypt(temp))
	}
}

func (p *PaillierContract) TestAggregate(ctx contractapi.TransactionContextInterface) float64 {
	fmt.Println("TestAggregate:------------------------------------------")
	var LEN = len(DATA_POOL)
	fmt.Println("测试数据量:", LEN)
	fmt.Println("开始测试......")
	fmt.Println("明文求和:", SUM)
	start := time.Now()
	var res int64 = 0
	for _, v := range DATA_POOL {
		res += v
	}
	end := time.Since(start).Milliseconds()
	fmt.Println("密文求和解密结果:", res)
	return float64(end)
}

func (p *PaillierContract) TestNTimes(ctx contractapi.TransactionContextInterface, times, n, bit int) {
	fmt.Println("TestNTimes:------------------------------------------")
	for i := 0; i < times; i++ {
		p.GenerateData(ctx, n, bit)
		start := time.Now()
		var res int64 = 0
		for _, v := range DATA_POOL {
			res += v
		}
		res = decrypt(res)
		end := time.Since(start).Milliseconds()
		fmt.Println(end)
	}
}
