// Factorial
/*
------------------------------------------------------
作者   : Black Ghost
日期   : 2018-12-6
版本   : 0.0.0
------------------------------------------------------
    计算自然数n的阶乘
------------------------------------------------------
输入   :
    n       自然数
输出   :
    sol     阶乘结果
    err     解出标志：false-未解出或达到步数上限；
                     true-全部解出
------------------------------------------------------
*/

package goNum

// Factorial 计算自然数n的阶乘
func Factorial(n int) int {
	//判断n
	if n < 0 {
		panic("Error in goNum.Factorial: n < 1")
	}
	if n == 0 {
		return 1
	}
	//计算
	var sol int = 1
	for i := n; i > 1; i-- {
		sol = sol * i
	}
	return sol
}
