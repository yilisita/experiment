package intvec

import (
	"fmt"
	"math"
	"math/big"
	"math/rand"
	"strconv"
	"time"

	"github.com/yilisita/goNum"
)

const (
	n      = 10
	l      = 100
	aBound = 100
	bBound = 1000
	tBound = 100
)

var w = math.Pow(2, 45)

func KeySwitch(M, c goNum.Matrix) goNum.Matrix {
	cstar := GetBitVector(c)
	return goNum.DotPruduct(M, cstar)
}

// 将十进制数字转化为二进制字符串
// counvertToBin有问题
func convertToBin(num float64) string {
	s := ""
	var isNegative = false
	if num < 0 {
		isNegative = true
		num = math.Abs(num) // 绝对值
	}

	numStr := strconv.FormatFloat(num, 'f', 0, 64)
	bigNumber, _ := new(big.Int).SetString(numStr, 10)
	// fmt.Sprintf可以返回想要的字符串, %b 将整数格式化表示,变量一定要是一个整数
	s = fmt.Sprintf("%b", bigNumber)
	s = fillStrLengthToL(s, l) // 填充成l = 100 位
	if isNegative {
		return "-" + s
	}
	return s
}

// 将字符串的长度填充到4
func fillStrLengthToL(s string, L int) string {
	var res = s
	if len(s) < L {
		var delt = L - len(s)
		for i := 0; i < delt; i++ {
			res = "0" + res
		}
	}
	return res
}

func reverse(str string) string {
	rs := []rune(str)
	len := len(rs)
	var tt []rune

	tt = make([]rune, 0)
	for i := 0; i < len; i++ {
		tt = append(tt, rs[len-i-1])
	}
	return string(tt[0:])
}

func GetRandomMatrix(row, col, bound int) goNum.Matrix {
	rand.Seed(time.Now().Unix())
	var A = goNum.ZeroMatrix(row, col)
	//var data = []float64
	var data = make([]float64, row*col)
	for i := 0; i < row*col; i++ {
		data[i] = float64(rand.Intn(bound))
	}
	A.Data = data
	return A
}

func GetBitMatrix(s goNum.Matrix) goNum.Matrix {
	var powers = make([]float64, l)
	for i := 0; i < l; i++ {
		powers[i] = math.Pow(2, float64(i))
	}
	var res = make([]float64, 0)
	for _, k := range s.Data {
		for _, j := range powers {
			res = append(res, k*j)
		}
	}
	var final = goNum.NewMatrix(s.Rows, s.Columns*l, res)
	return final
}

func GetBitVector(c goNum.Matrix) goNum.Matrix {
	var (
		res  = make([]float64, 0)
		sign = 1
		s    string
	)
	for _, i := range c.Data {
		s = convertToBin(i)
		if s[0] == '-' {
			sign = -1
			s = "0" + s[1:]
		}
		s = reverse(s)
		for _, j := range s {
			// 这里便利字符串有问题
			res = append(res, float64(int(j-48)*sign))
		}
	}
	A := goNum.NewMatrix(l*c.Rows*c.Columns, 1, res)
	return A
}

func GetSecretKey(T goNum.Matrix) goNum.Matrix {
	I := goNum.IdentityE(T.Rows)
	var (
		ISlice = make([][]float64, 0)
		TSlice = make([][]float64, 0)
	)
	ISlice = goNum.Matrix2ToSlices(I)
	TSlice = goNum.Matrix2ToSlices(T)
	for i := 0; i < T.Rows; i++ {
		ISlice[i] = append(ISlice[i], TSlice[i]...)
	}
	var res = make([]float64, 0)
	for _, s := range ISlice {
		for _, j := range s {
			res = append(res, j)
		}
	}
	A := goNum.NewMatrix(I.Rows, I.Columns+T.Columns, res)
	return A
}

func NearestInteger(x float64) float64 {
	return math.Floor((x + (w+1)/2) / w)
}

func Decrypt(S, c goNum.Matrix) goNum.Matrix {
	// 他写的矩阵乘法有问题
	sc := goNum.DotPruduct(S, c)
	x := make([]float64, 0)
	var temp float64
	for _, i := range sc.Data {
		temp = float64(NearestInteger(i)) // int(i)有问题
		if temp < 0 {
			temp = temp - 1
		}
		x = append(x, temp)
	}
	return goNum.NewMatrix(sc.Rows, 1, x)
}

func Encrypt(T, x goNum.Matrix) goNum.Matrix {
	I := goNum.IdentityE(x.Rows)
	var xSub = make([]float64, 0)
	xSub = append(xSub, x.Data...)
	var xS = goNum.NewMatrix(x.Rows, x.Columns, xSub)
	for i := 0; i < len(x.Data); i++ {
		xS.Data[i] *= w
	}
	return KeySwitch(KeySwitchMatrix(I, T), xS)
}

func KeySwitchMatrix(S, T goNum.Matrix) goNum.Matrix {
	sStar := GetBitMatrix(S)
	A := GetRandomMatrix(T.Columns, sStar.Columns, aBound)
	E := GetRandomMatrix(sStar.Rows, sStar.Columns, bBound)
	up1 := goNum.AddMatrix(sStar, E)
	up2 := goNum.SubMatrix(up1, goNum.DotPruduct(T, A))
	ASLice := goNum.Matrix2ToSlices(A)
	USlice := goNum.Matrix2ToSlices(up2)
	for _, j := range ASLice {
		USlice = append(USlice, j)
	}
	var res = make([]float64, 0)
	for _, s := range USlice {
		for _, j := range s {
			res = append(res, j)
		}
	}
	return goNum.NewMatrix(E.Rows+A.Rows, A.Columns, res)
}

//func main(){
//	var(
//		x1 = GetRandomMatrix(n, 1, 100)
//		x2 = GetRandomMatrix(n, 1, 100)
//		T = GetRandomMatrix(n,n, tBound)
//		S = GetSecretKey(T)
//		c1 = Encrypt(T, x1)
//		c2 = Encrypt(T, x2)
//	)
//
//	//fmt.Println(x1)
//	//fmt.Println(p1)
//	//加法
//	fmt.Println("直接计算:", goNum.AddMatrix(x1, x2).Data)
//	fmt.Println("加密计算：", Decrypt(S, goNum.AddMatrix(c1, c2)).Data)

//线性变换
