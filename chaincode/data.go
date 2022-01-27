// 实验用到的测试数据
// 变量的命名规则：
//  var Data_[n]_[bit]
// 			-- 所有变量以Data开头,
// 			-- 第一个数字表示数据量;
// 			-- 第二个数字表示每个数的位数；
// 	e.g. Data_100_3表示该切片中有100个数据，每个数据都是3位数
package chaincode

var DataIndex = map[int]([]int64){
	1:  Data_10_2,
	2:  Data_10_3,
	3:  Data_10_4,
	4:  Data_10_5,
	5:  Data_20_2,
	6:  Data_20_3,
	7:  Data_20_4,
	8:  Data_20_5,
	9:  Data_30_2,
	10: Data_30_3,
	11: Data_30_4,
	12: Data_30_5,
	13: Data_40_2,
	14: Data_40_3,
	15: Data_40_4,
	16: Data_40_5,
	17: Data_50_2,
	18: Data_50_3,
	19: Data_50_4,
	20: Data_50_5,
	21: Data_60_2,
	22: Data_60_3,
	23: Data_60_4,
	24: Data_60_5,
	25: Data_70_2,
	26: Data_70_3,
	27: Data_70_4,
	28: Data_70_5,
	29: Data_80_2,
	30: Data_80_3,
	31: Data_80_4,
	32: Data_80_5,
	33: Data_90_2,
	34: Data_90_3,
	35: Data_90_4,
	36: Data_90_5,
	37: Data_100_2,
	38: Data_100_3,
	39: Data_100_4,
	40: Data_100_5,
}

var Data_10_2 = []int64{

	54,
	27,
	80,
	79,
	95,
	66,
	66,
	72,
	12,
	14,
}
var Data_10_3 = []int64{

	554,
	527,
	180,
	179,
	295,
	566,
	266,
	572,
	212,
	404,
}
var Data_10_4 = []int64{

	2554,
	5527,
	2180,
	4179,
	3295,
	5566,
	5266,
	1572,
	8212,
	4404,
}
var Data_10_5 = []int64{

	12554,
	95527,
	82180,
	64179,
	33295,
	55566,
	85266,
	30572,
	18212,
	64404,
}
var Data_20_2 = []int64{

	54,
	27,
	80,
	79,
	95,
	66,
	66,
	72,
	12,
	14,
	70,
	40,
	66,
	91,
	14,
	61,
	18,
	45,
	14,
	18,
}
var Data_20_3 = []int64{

	554,
	527,
	180,
	179,
	295,
	566,
	266,
	572,
	212,
	404,
	170,
	240,
	966,
	291,
	514,
	561,
	818,
	545,
	714,
	308,
}
var Data_20_4 = []int64{

	2554,
	5527,
	2180,
	4179,
	3295,
	5566,
	5266,
	1572,
	8212,
	4404,
	5070,
	1240,
	6966,
	1291,
	1514,
	9561,
	3818,
	1545,
	9714,
	1308,
}
var Data_20_5 = []int64{

	12554,
	95527,
	82180,
	64179,
	33295,
	55566,
	85266,
	30572,
	18212,
	64404,
	15070,
	50240,
	36966,
	91291,
	20514,
	59561,
	93818,
	61545,
	69714,
	51308,
}
var Data_30_2 = []int64{

	54,
	27,
	80,
	79,
	95,
	66,
	66,
	72,
	12,
	14,
	70,
	40,
	66,
	91,
	14,
	61,
	18,
	45,
	14,
	18,
	96,
	90,
	19,
	80,
	48,
	75,
	83,
	19,
	28,
	56,
}
var Data_30_3 = []int64{

	554,
	527,
	180,
	179,
	295,
	566,
	266,
	572,
	212,
	404,
	170,
	240,
	966,
	291,
	514,
	561,
	818,
	545,
	714,
	308,
	796,
	590,
	819,
	580,
	648,
	275,
	583,
	809,
	628,
	256,
}
var Data_30_4 = []int64{

	2554,
	5527,
	2180,
	4179,
	3295,
	5566,
	5266,
	1572,
	8212,
	4404,
	5070,
	1240,
	6966,
	1291,
	1514,
	9561,
	3818,
	1545,
	9714,
	1308,
	3796,
	7590,
	6819,
	4580,
	4648,
	4275,
	4583,
	5809,
	1628,
	9256,
}
var Data_30_5 = []int64{

	12554,
	95527,
	82180,
	64179,
	33295,
	55566,
	85266,
	30572,
	18212,
	64404,
	15070,
	50240,
	36966,
	91291,
	20514,
	59561,
	93818,
	61545,
	69714,
	51308,
	93796,
	77590,
	96819,
	24580,
	34648,
	84275,
	84583,
	85809,
	51628,
	59256,
}
var Data_40_2 = []int64{

	54,
	27,
	80,
	79,
	95,
	66,
	66,
	72,
	12,
	14,
	70,
	40,
	66,
	91,
	14,
	61,
	18,
	45,
	14,
	18,
	96,
	90,
	19,
	80,
	48,
	75,
	83,
	19,
	28,
	56,
	43,
	22,
	10,
	61,
	24,
	44,
	17,
	17,
	66,
	87,
}
var Data_40_3 = []int64{

	554,
	527,
	180,
	179,
	295,
	566,
	266,
	572,
	212,
	404,
	170,
	240,
	966,
	291,
	514,
	561,
	818,
	545,
	714,
	308,
	796,
	590,
	819,
	580,
	648,
	275,
	583,
	809,
	628,
	256,
	643,
	522,
	810,
	561,
	524,
	144,
	917,
	817,
	866,
	187,
}
var Data_40_4 = []int64{

	2554,
	5527,
	2180,
	4179,
	3295,
	5566,
	5266,
	1572,
	8212,
	4404,
	5070,
	1240,
	6966,
	1291,
	1514,
	9561,
	3818,
	1545,
	9714,
	1308,
	3796,
	7590,
	6819,
	4580,
	4648,
	4275,
	4583,
	5809,
	1628,
	9256,
	6643,
	6522,
	5810,
	2561,
	6524,
	5144,
	2917,
	7817,
	1866,
	7087,
}
var Data_40_5 = []int64{

	12554,
	95527,
	82180,
	64179,
	33295,
	55566,
	85266,
	30572,
	18212,
	64404,
	15070,
	50240,
	36966,
	91291,
	20514,
	59561,
	93818,
	61545,
	69714,
	51308,
	93796,
	77590,
	96819,
	24580,
	34648,
	84275,
	84583,
	85809,
	51628,
	59256,
	96643,
	96522,
	15810,
	82561,
	16524,
	45144,
	12917,
	97817,
	31866,
	97087,
}
var Data_50_2 = []int64{

	54,
	27,
	80,
	79,
	95,
	66,
	66,
	72,
	12,
	14,
	70,
	40,
	66,
	91,
	14,
	61,
	18,
	45,
	14,
	18,
	96,
	90,
	19,
	80,
	48,
	75,
	83,
	19,
	28,
	56,
	43,
	22,
	10,
	61,
	24,
	44,
	17,
	17,
	66,
	87,
	72,
	23,
	15,
	10,
	14,
	53,
	18,
	61,
	55,
	76,
}
var Data_50_3 = []int64{

	554,
	527,
	180,
	179,
	295,
	566,
	266,
	572,
	212,
	404,
	170,
	240,
	966,
	291,
	514,
	561,
	818,
	545,
	714,
	308,
	796,
	590,
	819,
	580,
	648,
	275,
	583,
	809,
	628,
	256,
	643,
	522,
	810,
	561,
	524,
	144,
	917,
	817,
	866,
	187,
	172,
	823,
	805,
	900,
	414,
	553,
	418,
	561,
	355,
	276,
}
var Data_50_4 = []int64{

	2554,
	5527,
	2180,
	4179,
	3295,
	5566,
	5266,
	1572,
	8212,
	4404,
	5070,
	1240,
	6966,
	1291,
	1514,
	9561,
	3818,
	1545,
	9714,
	1308,
	3796,
	7590,
	6819,
	4580,
	4648,
	4275,
	4583,
	5809,
	1628,
	9256,
	6643,
	6522,
	5810,
	2561,
	6524,
	5144,
	2917,
	7817,
	1866,
	7087,
	9172,
	1823,
	8805,
	8900,
	8414,
	1553,
	3418,
	6561,
	1355,
	5276,
}
var Data_50_5 = []int64{

	12554,
	95527,
	82180,
	64179,
	33295,
	55566,
	85266,
	30572,
	18212,
	64404,
	15070,
	50240,
	36966,
	91291,
	20514,
	59561,
	93818,
	61545,
	69714,
	51308,
	93796,
	77590,
	96819,
	24580,
	34648,
	84275,
	84583,
	85809,
	51628,
	59256,
	96643,
	96522,
	15810,
	82561,
	16524,
	45144,
	12917,
	97817,
	31866,
	97087,
	89172,
	80823,
	58805,
	18900,
	48414,
	11553,
	53418,
	66561,
	50355,
	45276,
}
var Data_60_2 = []int64{

	54,
	27,
	80,
	79,
	95,
	66,
	66,
	72,
	12,
	14,
	70,
	40,
	66,
	91,
	14,
	61,
	18,
	45,
	14,
	18,
	96,
	90,
	19,
	80,
	48,
	75,
	83,
	19,
	28,
	56,
	43,
	22,
	10,
	61,
	24,
	44,
	17,
	17,
	66,
	87,
	72,
	23,
	15,
	10,
	14,
	53,
	18,
	61,
	55,
	76,
	94,
	37,
	10,
	43,
	39,
	11,
	31,
	97,
	11,
	16,
}
var Data_60_3 = []int64{

	554,
	527,
	180,
	179,
	295,
	566,
	266,
	572,
	212,
	404,
	170,
	240,
	966,
	291,
	514,
	561,
	818,
	545,
	714,
	308,
	796,
	590,
	819,
	580,
	648,
	275,
	583,
	809,
	628,
	256,
	643,
	522,
	810,
	561,
	524,
	144,
	917,
	817,
	866,
	187,
	172,
	823,
	805,
	900,
	414,
	553,
	418,
	561,
	355,
	276,
	694,
	537,
	310,
	543,
	339,
	501,
	331,
	797,
	101,
	716,
}
var Data_60_4 = []int64{

	2554,
	5527,
	2180,
	4179,
	3295,
	5566,
	5266,
	1572,
	8212,
	4404,
	5070,
	1240,
	6966,
	1291,
	1514,
	9561,
	3818,
	1545,
	9714,
	1308,
	3796,
	7590,
	6819,
	4580,
	4648,
	4275,
	4583,
	5809,
	1628,
	9256,
	6643,
	6522,
	5810,
	2561,
	6524,
	5144,
	2917,
	7817,
	1866,
	7087,
	9172,
	1823,
	8805,
	8900,
	8414,
	1553,
	3418,
	6561,
	1355,
	5276,
	4694,
	4537,
	7310,
	4543,
	2339,
	6501,
	1331,
	3797,
	3101,
	6716,
}
var Data_60_5 = []int64{

	12554,
	95527,
	82180,
	64179,
	33295,
	55566,
	85266,
	30572,
	18212,
	64404,
	15070,
	50240,
	36966,
	91291,
	20514,
	59561,
	93818,
	61545,
	69714,
	51308,
	93796,
	77590,
	96819,
	24580,
	34648,
	84275,
	84583,
	85809,
	51628,
	59256,
	96643,
	96522,
	15810,
	82561,
	16524,
	45144,
	12917,
	97817,
	31866,
	97087,
	89172,
	80823,
	58805,
	18900,
	48414,
	11553,
	53418,
	66561,
	50355,
	45276,
	64694,
	74537,
	47310,
	14543,
	82339,
	66501,
	11331,
	43797,
	23101,
	46716,
}
var Data_70_2 = []int64{

	54,
	27,
	80,
	79,
	95,
	66,
	66,
	72,
	12,
	14,
	70,
	40,
	66,
	91,
	14,
	61,
	18,
	45,
	14,
	18,
	96,
	90,
	19,
	80,
	48,
	75,
	83,
	19,
	28,
	56,
	43,
	22,
	10,
	61,
	24,
	44,
	17,
	17,
	66,
	87,
	72,
	23,
	15,
	10,
	14,
	53,
	18,
	61,
	55,
	76,
	94,
	37,
	10,
	43,
	39,
	11,
	31,
	97,
	11,
	16,
	16,
	76,
	33,
	29,
	14,
	10,
	31,
	76,
	77,
	92,
}
var Data_70_3 = []int64{

	554,
	527,
	180,
	179,
	295,
	566,
	266,
	572,
	212,
	404,
	170,
	240,
	966,
	291,
	514,
	561,
	818,
	545,
	714,
	308,
	796,
	590,
	819,
	580,
	648,
	275,
	583,
	809,
	628,
	256,
	643,
	522,
	810,
	561,
	524,
	144,
	917,
	817,
	866,
	187,
	172,
	823,
	805,
	900,
	414,
	553,
	418,
	561,
	355,
	276,
	694,
	537,
	310,
	543,
	339,
	501,
	331,
	797,
	101,
	716,
	616,
	676,
	533,
	129,
	314,
	110,
	831,
	176,
	477,
	492,
}
var Data_70_4 = []int64{

	2554,
	5527,
	2180,
	4179,
	3295,
	5566,
	5266,
	1572,
	8212,
	4404,
	5070,
	1240,
	6966,
	1291,
	1514,
	9561,
	3818,
	1545,
	9714,
	1308,
	3796,
	7590,
	6819,
	4580,
	4648,
	4275,
	4583,
	5809,
	1628,
	9256,
	6643,
	6522,
	5810,
	2561,
	6524,
	5144,
	2917,
	7817,
	1866,
	7087,
	9172,
	1823,
	8805,
	8900,
	8414,
	1553,
	3418,
	6561,
	1355,
	5276,
	4694,
	4537,
	7310,
	4543,
	2339,
	6501,
	1331,
	3797,
	3101,
	6716,
	1616,
	3676,
	1533,
	5129,
	7314,
	3110,
	5831,
	1176,
	1477,
	3492,
}
var Data_70_5 = []int64{

	12554,
	95527,
	82180,
	64179,
	33295,
	55566,
	85266,
	30572,
	18212,
	64404,
	15070,
	50240,
	36966,
	91291,
	20514,
	59561,
	93818,
	61545,
	69714,
	51308,
	93796,
	77590,
	96819,
	24580,
	34648,
	84275,
	84583,
	85809,
	51628,
	59256,
	96643,
	96522,
	15810,
	82561,
	16524,
	45144,
	12917,
	97817,
	31866,
	97087,
	89172,
	80823,
	58805,
	18900,
	48414,
	11553,
	53418,
	66561,
	50355,
	45276,
	64694,
	74537,
	47310,
	14543,
	82339,
	66501,
	11331,
	43797,
	23101,
	46716,
	10616,
	53676,
	90533,
	85129,
	77314,
	33110,
	25831,
	81176,
	11477,
	13492,
}
var Data_80_2 = []int64{

	54,
	27,
	80,
	79,
	95,
	66,
	66,
	72,
	12,
	14,
	70,
	40,
	66,
	91,
	14,
	61,
	18,
	45,
	14,
	18,
	96,
	90,
	19,
	80,
	48,
	75,
	83,
	19,
	28,
	56,
	43,
	22,
	10,
	61,
	24,
	44,
	17,
	17,
	66,
	87,
	72,
	23,
	15,
	10,
	14,
	53,
	18,
	61,
	55,
	76,
	94,
	37,
	10,
	43,
	39,
	11,
	31,
	97,
	11,
	16,
	16,
	76,
	33,
	29,
	14,
	10,
	31,
	76,
	77,
	92,
	58,
	97,
	14,
	88,
	71,
	32,
	40,
	24,
	50,
	98,
}
var Data_80_3 = []int64{

	554,
	527,
	180,
	179,
	295,
	566,
	266,
	572,
	212,
	404,
	170,
	240,
	966,
	291,
	514,
	561,
	818,
	545,
	714,
	308,
	796,
	590,
	819,
	580,
	648,
	275,
	583,
	809,
	628,
	256,
	643,
	522,
	810,
	561,
	524,
	144,
	917,
	817,
	866,
	187,
	172,
	823,
	805,
	900,
	414,
	553,
	418,
	561,
	355,
	276,
	694,
	537,
	310,
	543,
	339,
	501,
	331,
	797,
	101,
	716,
	616,
	676,
	533,
	129,
	314,
	110,
	831,
	176,
	477,
	492,
	958,
	297,
	104,
	588,
	971,
	432,
	240,
	824,
	950,
	498,
}
var Data_80_4 = []int64{

	2554,
	5527,
	2180,
	4179,
	3295,
	5566,
	5266,
	1572,
	8212,
	4404,
	5070,
	1240,
	6966,
	1291,
	1514,
	9561,
	3818,
	1545,
	9714,
	1308,
	3796,
	7590,
	6819,
	4580,
	4648,
	4275,
	4583,
	5809,
	1628,
	9256,
	6643,
	6522,
	5810,
	2561,
	6524,
	5144,
	2917,
	7817,
	1866,
	7087,
	9172,
	1823,
	8805,
	8900,
	8414,
	1553,
	3418,
	6561,
	1355,
	5276,
	4694,
	4537,
	7310,
	4543,
	2339,
	6501,
	1331,
	3797,
	3101,
	6716,
	1616,
	3676,
	1533,
	5129,
	7314,
	3110,
	5831,
	1176,
	1477,
	3492,
	8958,
	2297,
	4104,
	9588,
	7971,
	2432,
	1240,
	5824,
	1950,
	3498,
}
var Data_80_5 = []int64{

	12554,
	95527,
	82180,
	64179,
	33295,
	55566,
	85266,
	30572,
	18212,
	64404,
	15070,
	50240,
	36966,
	91291,
	20514,
	59561,
	93818,
	61545,
	69714,
	51308,
	93796,
	77590,
	96819,
	24580,
	34648,
	84275,
	84583,
	85809,
	51628,
	59256,
	96643,
	96522,
	15810,
	82561,
	16524,
	45144,
	12917,
	97817,
	31866,
	97087,
	89172,
	80823,
	58805,
	18900,
	48414,
	11553,
	53418,
	66561,
	50355,
	45276,
	64694,
	74537,
	47310,
	14543,
	82339,
	66501,
	11331,
	43797,
	23101,
	46716,
	10616,
	53676,
	90533,
	85129,
	77314,
	33110,
	25831,
	81176,
	11477,
	13492,
	98958,
	12297,
	44104,
	49588,
	57971,
	52432,
	91240,
	95824,
	60950,
	83498,
}
var Data_90_2 = []int64{

	54,
	27,
	80,
	79,
	95,
	66,
	66,
	72,
	12,
	14,
	70,
	40,
	66,
	91,
	14,
	61,
	18,
	45,
	14,
	18,
	96,
	90,
	19,
	80,
	48,
	75,
	83,
	19,
	28,
	56,
	43,
	22,
	10,
	61,
	24,
	44,
	17,
	17,
	66,
	87,
	72,
	23,
	15,
	10,
	14,
	53,
	18,
	61,
	55,
	76,
	94,
	37,
	10,
	43,
	39,
	11,
	31,
	97,
	11,
	16,
	16,
	76,
	33,
	29,
	14,
	10,
	31,
	76,
	77,
	92,
	58,
	97,
	14,
	88,
	71,
	32,
	40,
	24,
	50,
	98,
	21,
	25,
	92,
	40,
	50,
	15,
	79,
	74,
	59,
	63,
}
var Data_90_3 = []int64{

	554,
	527,
	180,
	179,
	295,
	566,
	266,
	572,
	212,
	404,
	170,
	240,
	966,
	291,
	514,
	561,
	818,
	545,
	714,
	308,
	796,
	590,
	819,
	580,
	648,
	275,
	583,
	809,
	628,
	256,
	643,
	522,
	810,
	561,
	524,
	144,
	917,
	817,
	866,
	187,
	172,
	823,
	805,
	900,
	414,
	553,
	418,
	561,
	355,
	276,
	694,
	537,
	310,
	543,
	339,
	501,
	331,
	797,
	101,
	716,
	616,
	676,
	533,
	129,
	314,
	110,
	831,
	176,
	477,
	492,
	958,
	297,
	104,
	588,
	971,
	432,
	240,
	824,
	950,
	498,
	521,
	425,
	992,
	540,
	850,
	105,
	179,
	274,
	259,
	163,
}
var Data_90_4 = []int64{

	2554,
	5527,
	2180,
	4179,
	3295,
	5566,
	5266,
	1572,
	8212,
	4404,
	5070,
	1240,
	6966,
	1291,
	1514,
	9561,
	3818,
	1545,
	9714,
	1308,
	3796,
	7590,
	6819,
	4580,
	4648,
	4275,
	4583,
	5809,
	1628,
	9256,
	6643,
	6522,
	5810,
	2561,
	6524,
	5144,
	2917,
	7817,
	1866,
	7087,
	9172,
	1823,
	8805,
	8900,
	8414,
	1553,
	3418,
	6561,
	1355,
	5276,
	4694,
	4537,
	7310,
	4543,
	2339,
	6501,
	1331,
	3797,
	3101,
	6716,
	1616,
	3676,
	1533,
	5129,
	7314,
	3110,
	5831,
	1176,
	1477,
	3492,
	8958,
	2297,
	4104,
	9588,
	7971,
	2432,
	1240,
	5824,
	1950,
	3498,
	3521,
	4425,
	1992,
	2540,
	7850,
	7005,
	9079,
	3274,
	4259,
	2163,
}
var Data_90_5 = []int64{

	12554,
	95527,
	82180,
	64179,
	33295,
	55566,
	85266,
	30572,
	18212,
	64404,
	15070,
	50240,
	36966,
	91291,
	20514,
	59561,
	93818,
	61545,
	69714,
	51308,
	93796,
	77590,
	96819,
	24580,
	34648,
	84275,
	84583,
	85809,
	51628,
	59256,
	96643,
	96522,
	15810,
	82561,
	16524,
	45144,
	12917,
	97817,
	31866,
	97087,
	89172,
	80823,
	58805,
	18900,
	48414,
	11553,
	53418,
	66561,
	50355,
	45276,
	64694,
	74537,
	47310,
	14543,
	82339,
	66501,
	11331,
	43797,
	23101,
	46716,
	10616,
	53676,
	90533,
	85129,
	77314,
	33110,
	25831,
	81176,
	11477,
	13492,
	98958,
	12297,
	44104,
	49588,
	57971,
	52432,
	91240,
	95824,
	60950,
	83498,
	13521,
	24425,
	70992,
	52540,
	17850,
	27005,
	69079,
	13274,
	64259,
	62163,
}
var Data_100_2 = []int64{

	54,
	27,
	80,
	79,
	95,
	66,
	66,
	72,
	12,
	14,
	70,
	40,
	66,
	91,
	14,
	61,
	18,
	45,
	14,
	18,
	96,
	90,
	19,
	80,
	48,
	75,
	83,
	19,
	28,
	56,
	43,
	22,
	10,
	61,
	24,
	44,
	17,
	17,
	66,
	87,
	72,
	23,
	15,
	10,
	14,
	53,
	18,
	61,
	55,
	76,
	94,
	37,
	10,
	43,
	39,
	11,
	31,
	97,
	11,
	16,
	16,
	76,
	33,
	29,
	14,
	10,
	31,
	76,
	77,
	92,
	58,
	97,
	14,
	88,
	71,
	32,
	40,
	24,
	50,
	98,
	21,
	25,
	92,
	40,
	50,
	15,
	79,
	74,
	59,
	63,
	93,
	21,
	22,
	94,
	15,
	83,
	24,
	56,
	23,
	36,
}
var Data_100_3 = []int64{

	554,
	527,
	180,
	179,
	295,
	566,
	266,
	572,
	212,
	404,
	170,
	240,
	966,
	291,
	514,
	561,
	818,
	545,
	714,
	308,
	796,
	590,
	819,
	580,
	648,
	275,
	583,
	809,
	628,
	256,
	643,
	522,
	810,
	561,
	524,
	144,
	917,
	817,
	866,
	187,
	172,
	823,
	805,
	900,
	414,
	553,
	418,
	561,
	355,
	276,
	694,
	537,
	310,
	543,
	339,
	501,
	331,
	797,
	101,
	716,
	616,
	676,
	533,
	129,
	314,
	110,
	831,
	176,
	477,
	492,
	958,
	297,
	104,
	588,
	971,
	432,
	240,
	824,
	950,
	498,
	521,
	425,
	992,
	540,
	850,
	105,
	179,
	274,
	259,
	163,
	193,
	721,
	122,
	594,
	305,
	383,
	624,
	156,
	123,
	136,
}
var Data_100_4 = []int64{

	2554,
	5527,
	2180,
	4179,
	3295,
	5566,
	5266,
	1572,
	8212,
	4404,
	5070,
	1240,
	6966,
	1291,
	1514,
	9561,
	3818,
	1545,
	9714,
	1308,
	3796,
	7590,
	6819,
	4580,
	4648,
	4275,
	4583,
	5809,
	1628,
	9256,
	6643,
	6522,
	5810,
	2561,
	6524,
	5144,
	2917,
	7817,
	1866,
	7087,
	9172,
	1823,
	8805,
	8900,
	8414,
	1553,
	3418,
	6561,
	1355,
	5276,
	4694,
	4537,
	7310,
	4543,
	2339,
	6501,
	1331,
	3797,
	3101,
	6716,
	1616,
	3676,
	1533,
	5129,
	7314,
	3110,
	5831,
	1176,
	1477,
	3492,
	8958,
	2297,
	4104,
	9588,
	7971,
	2432,
	1240,
	5824,
	1950,
	3498,
	3521,
	4425,
	1992,
	2540,
	7850,
	7005,
	9079,
	3274,
	4259,
	2163,
	2193,
	9721,
	1122,
	7594,
	7305,
	4383,
	1624,
	6056,
	2023,
	6036,
}
var Data_100_5 = []int64{

	12554,
	95527,
	82180,
	64179,
	33295,
	55566,
	85266,
	30572,
	18212,
	64404,
	15070,
	50240,
	36966,
	91291,
	20514,
	59561,
	93818,
	61545,
	69714,
	51308,
	93796,
	77590,
	96819,
	24580,
	34648,
	84275,
	84583,
	85809,
	51628,
	59256,
	96643,
	96522,
	15810,
	82561,
	16524,
	45144,
	12917,
	97817,
	31866,
	97087,
	89172,
	80823,
	58805,
	18900,
	48414,
	11553,
	53418,
	66561,
	50355,
	45276,
	64694,
	74537,
	47310,
	14543,
	82339,
	66501,
	11331,
	43797,
	23101,
	46716,
	10616,
	53676,
	90533,
	85129,
	77314,
	33110,
	25831,
	81176,
	11477,
	13492,
	98958,
	12297,
	44104,
	49588,
	57971,
	52432,
	91240,
	95824,
	60950,
	83498,
	13521,
	24425,
	70992,
	52540,
	17850,
	27005,
	69079,
	13274,
	64259,
	62163,
	12193,
	19721,
	10122,
	27594,
	27305,
	44383,
	30624,
	96056,
	12023,
	56036,
}
