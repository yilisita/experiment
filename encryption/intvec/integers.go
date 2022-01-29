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
	s = fmt.Sprintf("%b", bigNumber)
	s = fillStrLengthToL(s, l)
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

// TODO: when doing encryption, we should use a public key, in the paper, that is M
// HOW to fix this ?
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

// S: the original private key
// T: the "T" part of the new private key
// return M:
//			M.Rows = S.Rows + T.Columns
//  		M.Columns = S.Columns
// Therefor, we could only manually adjust T.Columns to reshape new ciphertext's row
// Thus we could reduce the ciphertext's dimensions
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

// GetInnerProduct receives a key switching matrix M, two encrypted ciphertexts, i.e. c1 and c2,
// which are equal in length and width, and returns the result of their inner product, which
// should be decrypted with a new private key constructed by the ciphertexts' private keys
// (this means that the input ciphertexts may have different or the same keys).
func GetInnerProduct(c1, c2, M goNum.Matrix) goNum.Matrix {
	if c1.Rows != c2.Rows || c1.Columns != c2.Columns {
		panic("Unmatched shape of c1 and c2: c1.Rows/c1.Columns should be equal c2.Rows/Columns.")
	}

	if M.Columns != c1.Rows*c2.Rows*l {
		panic("Cannot use M to reduce the dimension of vec(c1 * c2'): M.Columns and vec(c1 * c2').Rows unmatched.")
	}
	// calculate the new ciphertext
	// c1c2T = c1 * c2'
	var c1c2T = goNum.DotPruduct(c1, c2.Transpose())

	// construct vec(c1c2T)
	var flattenc1c2T []float64
	for i := 0; i < c1c2T.Rows; i++ {
		flattenc1c2T = append(flattenc1c2T, c1c2T.RowOfMatrix(i)...)
	}

	// calculate vec(c1c2T) / w
	for k, v := range flattenc1c2T {
		flattenc1c2T[k] = v / w
	}
	var flattenc1c2TMatrix = goNum.NewMatrix(c1.Rows*c2.Rows, 1, flattenc1c2T)
	// do the dimension reduction
	return KeySwitch(M, flattenc1c2TMatrix)
}

// GetInnerProductKey compute a new temporary private key which is
// very long and cannot be used directly to decrypt the new
// ciphertext returned by GetInnerProduct.
func GetInnerProductLongKey(s1, s2 goNum.Matrix) goNum.Matrix {
	if s1.Rows != s2.Rows || s1.Columns != s2.Columns {
		panic("Unmatched shape of s1 and s2: s1.Rows/s1.Columns should be equal s2.Rows/s2.Columns.")
	}

	var s1Ts2 = goNum.DotPruduct(s1.Transpose(), s2)
	var s1Ts2Flatten []float64
	for i := 0; i < s1Ts2.Rows; i++ {
		s1Ts2Flatten = append(s1Ts2Flatten, s1Ts2.RowOfMatrix(i)...)
	}
	return goNum.NewMatrix(1, s1Ts2.Rows*s1Ts2.Rows, s1Ts2Flatten)
}

// Refer to KeySwitchMatrix, we could only adjust the columns of T, i.e. the "T" part of the new private key
// which could be generated with method "GetRandomKey" to shape the new ciphertext's rows = S.Rows + T.Columns.
// Because S.Rows = 1 (under the circumstance of Inner Product), so we could reshape ciphertext's dimension to n,
// by adjusting T.Columns = n - 1,
//				i.e. var T = GetRandomMatrix(1, n-1, bound)
//											 |
// ps: recall method "GetSecretKey", we compute a key, s, whose Rows equal T.Rows
// @Para: s = vec(s1Ts2), that is the key generated by GetInnerProductKey
// @Return: M: the key switching matrix to reduce ciphertext's dimension
//			S: the final private key to decrypt the dimension-reduced ciphertext
func GetInnerProductSwitchingMatrix(s goNum.Matrix) (goNum.Matrix, goNum.Matrix) {
	var n = int(math.Sqrt(float64(s.Columns)))
	var T = GetRandomMatrix(1, n-1, tBound)
	var S = GetSecretKey(T)
	// the final new key must be returned, otherwise we have no way to obtain it
	return KeySwitchMatrix(s, T), S
}
