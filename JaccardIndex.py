#!coding=utf8

import io
import numpy as np
import pandas as pd

# 返回rfile中域名的特征向量KMeans聚类结果
# 每行格式：[域名, KMeans聚类簇编号]
def getFeatureVector(rfile):
	fv = []
	with io.open(rfile, "r") as f:
		for line in f.readlines():
			fv.append(eval(line))

	return fv

# 返回rfile中域名之间编辑距离的DBScan聚类结果
# 每行格式：[域名, DBScan聚类簇编号]
def getLevenshteinDistance(rfile):
	ld = []
	with io.open(rfile, "r") as f:
		for line in f.readlines():
			ld.append(eval(line))

	return ld

# 计算KMeans聚类簇A，DBScan聚类簇B的Jaccard Index = (A ∩ B) / (A ∪ B)
# 参数：
# 	arr：域名原始数据矩阵。每行格式：[域名, KMeans聚类簇编号, DBScan聚类簇编号]
#	i：当前KMeans聚类簇编号
#	j：当前DBScan聚类簇编号
# 返回值：Jaccard Index(A, B)
def jaccardIndex(arr, i, j):
	setA = set()
	setB = set()

	for item in arr:
		# setA中加入KMeans聚类簇编号为i的域名
		if int(item[1]) == i:
			setA.add(item[0])
		# setA中加入DBScan聚类簇编号为j的域名
		if int(item[2]) == j:
			setB.add(item[0])

	# 并集不为空时才计算
	# 保留小数点后6位
	if len(setA | setB) != 0:
		return round(len(setA & setB) / len(setA | setB), 6)
	else:
		return 0

# 主函数
# 从fv，ld分别获取所有KMeans聚类簇和所有DBScan聚类簇
# 对所有KMeans聚类簇和所有DBScan聚类簇，两两计算Jaccard Index
# 结果写入wfile
def main(fv, ld, wfile):
	# 所有KMeans聚类簇（格式：[域名, KMeans聚类簇编号]）
	fv_raw = pd.DataFrame(np.array(getFeatureVector(fv)), 
		columns=["domain", "fv"])
	# 所有DBScan聚类簇（格式：[域名, DBScan聚类簇编号]）
	ld_raw = pd.DataFrame(np.array(getLevenshteinDistance(ld)), 
		columns=["domain", "ld"])

	# 以域名为连接列，水平合并所有KMeans聚类簇和所有DBScan聚类簇，取交集
	# 最终格式：[域名, KMeans聚类簇编号, DBScan聚类簇编号]
	fv_ld = pd.merge(fv_raw, ld_raw, on="domain", how="inner")
	fv_ld = np.array(fv_ld)

	# 计算KMeans聚类簇和DBScan聚类簇的个数
	size_fv = int(max(fv_raw["fv"], key=lambda x: int(x))) + 1
	size_ld = int(max(ld_raw["ld"], key=lambda x: int(x))) + 2
	print(size_fv, size_ld)
	
	# 初始化Jaccard Index矩阵
	ji = [[0.0 for y in range(size_ld)] for x in range(size_fv)]

	# 簇之间两两计算Jaccard Index
	for i in range(size_fv):
		for j in range(size_ld):
			ji[i][j] = jaccardIndex(fv_ld, i, j)

	with io.open(wfile, "w") as f:
		for item in ji:
			f.write(str(item) + "\n")


if __name__ == '__main__':
	main("data/feature_test_kmeans.dat", 
		"data/levenshtein_dbscan.dat", 
		"data/jaccard_index.dat")