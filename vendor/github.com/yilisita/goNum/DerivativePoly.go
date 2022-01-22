// DerivativePoly
/*
------------------------------------------------------
作者   : Black Ghost
日期   : 2018-12-25
版本   : 0.0.0
------------------------------------------------------
    求单变量多项式n阶导数
理论：

------------------------------------------------------
输入   :
    A       按幂次连续增加的系数向量,(Nn+1)x1,Nn为最高幂次
    n       求导次数
输出   :
    sol     解,(Nn+1-n)x1
    err     解出标志：false-未解出或达到边界；
                     true-全部解出
------------------------------------------------------
*/

package goNum

// DerivativePoly 求单变量多项式n阶导数
func DerivativePoly(A Matrix, n int) (Matrix, bool) {
	/*
	       求单变量多项式n阶导数
	   输入   :
	       A       按幂次连续增加的系数向量,(Nn+1)x1,Nn为最高幂次
	       n       求导次数
	   输出   :
	       sol     解,(Nn+1-n)x1
	       err     解出标志：false-未解出或达到边界；
	                        true-全部解出
	*/
	//判断求导次数与最高幂次关系
	Nn := A.Rows - 1
	if n > Nn+1 {
		panic("Error in goNum.DerivativePoly: Derivative number greater than polynomial's order")
	}
	//Nn+1 = n
	if Nn+1 == n {
		return NewMatrix(1, 1, []float64{0.0}), true
	}

	sol := ZeroMatrix(Nn+1, 1)
	var lenSol int = Nn + 1
	var err bool = false

	//赋予soltemp初值
	for i := 0; i < Nn+1; i++ {
		sol.Data[i] = A.Data[i]
	}

	//求导计算
	for i := 1; i < n+1; i++ {
		for j := 1; j < lenSol; j++ {
			sol.Data[j-1] = float64(j) * sol.Data[j]
		}
		lenSol--
	}

	err = true
	return NewMatrix(lenSol, 1, sol.Data[:lenSol]), err
}
