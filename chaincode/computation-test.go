package chaincode

import (
	"fmt"
	"math/big"
	"time"

	//"math/rand"
	"test-algorithm/encryption/paillier"
	//"time"

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

// func (p *PaillierContract) EncryptData(ctx contractapi.TransactionContextInterface, data *[]int64) int64 {
// 	start := time.Now()
// 	for i, v := range *data {
// 		(*data)[i] = encrypt(v)
// 	}
// 	end := time.Since(start).Milliseconds()
// 	return end
// }

// 测试聚合运算，调用这个函数的时候测试数据也会被加密了
// 参数：测试数据的索引值
// 返回：返回加密过程的用时，聚合计算以及解密过程的总用时
func (p *PaillierContract) TestAggregate(ctx contractapi.TransactionContextInterface, index int) []int64 {
	fmt.Println("TestAggregate:------------------------------------------")
	var data = DataIndex[index]
	var LEN = len(data)
	fmt.Println("测试数据量:", LEN)
	fmt.Println("开始测试......")

	// 明文求和
	var sum int64 = 0
	for _, v := range data {
		sum += v
	}
	fmt.Println("明文求和:", sum)

	// 计时加密
	start := time.Now()
	for i, v := range data {
		data[i] = encrypt(v)
	}
	end := time.Since(start).Milliseconds()

	// 计算计时
	start1 := time.Now()
	var res int64 = 0
	for _, v := range data {
		res += v
	}
	end1 := time.Since(start1).Milliseconds()
	fmt.Println("密文求和解密结果:", decrypt(res))
	fmt.Println("用时(单位:ms):", end1)
	return []int64{end, end1}
}

// func (p *PaillierContract) TestNTimes(ctx contractapi.TransactionContextInterface, times, n, bit int) {
// 	fmt.Println("TestNTimes:------------------------------------------")
// 	for i := 0; i < times; i++ {
// 		var DATA_POOL = p.GenerateData(ctx, n, bit)
// 		start := time.Now()
// 		var res int64 = 0
// 		for _, v := range DATA_POOL {
// 			res += v
// 		}
// 		res = decrypt(res)
// 		end := time.Since(start).Milliseconds()
// 		fmt.Println(end)
// 	}
// }

func (p *PaillierContract) SayHi(ctx contractapi.TransactionContextInterface) string {
	err := ctx.GetStub().PutState("1", []byte("Hi"))
	if err != nil {
		return "Error"
	}
	fmt.Println("Hi, from Here")
	return "Hi"
}
