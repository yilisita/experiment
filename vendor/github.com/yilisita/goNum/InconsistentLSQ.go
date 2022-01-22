// InconsistentLSQ
/*
------------------------------------------------------
作者   : Black Ghost
日期   : 2018-12-11
版本   : 0.0.0
------------------------------------------------------
    求解矛盾方程组的最小二乘法（Least Square Method）
理论：
    对于矛盾方程组Ax=b，即

     n
    Sum aij*xj = bi   (i=1, 2, ..., N)
    j=1

    rank(A) = n (N > n)

    则A'Ax=A'b的唯一解为原矛盾方程组的最小二乘解

    参考 李信真, 车刚明, 欧阳洁, 等. 计算方法. 西北工业大学
       出版社, 2000, pp 130-135.
------------------------------------------------------
输入   :
    A       原方程组系数矩阵，Nxn
    b       原方程组值向量，Nx1
输出   :
    sol     解向量
    err     解出标志：false-未解出或达到步数上限；
                     true-全部解出
------------------------------------------------------
*/

package goNum

// InconsistentLSQ 求解矛盾方程组的最小二乘法（Least Square Method）
func InconsistentLSQ(A, b Matrix) (Matrix, bool) {
	/*
		求解矛盾方程组的最小二乘法（Least Square Method）
		输入   :
		    A       原方程组系数矩阵，Nxn
		    b       原方程组值向量，Nx1
		输出   :
		    sol     解向量
		    err     解出标志：false-未解出或达到步数上限；
		                     true-全部解出
	*/
	//判断A和b的行数是否对应
	if A.Rows != b.Rows {
		panic("Error in goNum.InconsistentLSQ: Rows of A and b are not equal")
	}

	//求解A'A和A'b
	AA := DotPruduct(A.Transpose(), A)
	Ab := DotPruduct(A.Transpose(), b)

	//转换矩阵为切片
	Atemp := Matrix2ToSlices(AA)
	btemp := Matrix1ToSlices(Ab)
	if (len(Atemp) != A.Columns) || (len(Atemp[0]) != A.Columns) || (len(btemp) != A.Columns) {
		panic("Error in goNum.InconsistentLSQ: Matrix to slices error")
	}
	//求解x向量，采用列主元消去法（LEs_ECPE）
	soltemp, err := LEs_ECPE(Atemp, btemp)
	if err != true {
		panic("Error in goNum.InconsistentLSQ: Solve error")
	}
	//转换切片为矩阵
	sol := Slices1ToMatrix(soltemp)
	if sol.Rows != A.Columns {
		panic("Error in goNum.InconsistentLSQ: Slice to matrix error")
	}

	return sol, true
}
