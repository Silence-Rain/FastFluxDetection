#!coding=utf8

import sys
sys.path.append("../../")
from ctypes import *
import io
import os
import numpy as np
from sklearn.cluster import KMeans
from utils import plot

get_feature_vector = None

# 初始化C++接口调用
def initCppLibs():
	ll = cdll.LoadLibrary
	lib = ll("../../lib/libFeatureVector.so")
	global get_feature_vector
	# 生成函数指针
	init = lib.init
	get_feature_vector = lib.getFeatureVector
	get_feature_vector.argtypes = [c_char_p, c_char_p]	# 设置参数格式
	get_feature_vector.restype = None					# 设置返回值格式
	init()		# 接口内部初始化

	print("动态库libFeatureVector.so已加载！")

# 根据时间窗口取得测试集聚合IP后的结果
# 每行格式：[域名，[ip1, ip2, ...]，TTL，timestamp]
def cluster_by_window(test, test_res, window):
	cur_time = 1505115200# int(time.time())
	res = []
	with open(test, "r") as f:
		domains = []
		for line in f.readlines():
			temp = line.split(",")
			if cur_time > int(temp[3]) + window:
				continue
			if temp[0] not in domains:
				domains.append(temp[0])
				res.append([temp[0], [int(temp[1])], int(temp[2]), int(temp[3])])
			else:
				idx = domains.index(temp[0])
				res[idx][1].append(int(temp[1]))
	with open(test_res, "w") as fres:
		for item in res:
			fres.write(str(item) + "\n")

	print("域名的解析IP聚合 完成！")

# 根据mode取值确定聚类对象。0:二级域标签，1:三级域标签
# 获取rfile中域名的特征向量
# 每行格式：[域名, 特征向量...]
# 使用KMeans算法对对应标签的特征向量聚类
# 聚类结果写入wfile中。每行格式：[域名, 聚类簇编号]
def KMeansOfFeatureVector(rfile, wfile, mode=1):
	print("KMeans聚类 开始...")

	raw = []
	with io.open(rfile, "r") as f:
		for line in f.readlines():
			arr = line.split(",")
			temp = [arr[0]]

			# 提取二级域标签的特征向量
			if mode == 0:
				inds = [1,2,3,7,8,9,13,15,17]
				for i in inds:
					temp.append(arr[i])
			# 提取三级域标签的特征向量
			else:
				inds = [4,5,6,10,11,12,14,16,18]
				for i in inds:
					temp.append(arr[i])

			raw.append(temp)

	res = np.array(raw)
	# 用KMeans算法对特征向量聚类
	# 使用9维闵可夫斯基距离作为两数据点之间的距离
	# 使用参数：
	# 簇中心个数：10
	clst = KMeans(n_clusters=10, random_state=503)
	labels = clst.fit_predict(res[:,1:])
	print("当前域名标签: %s" % ("二级" if mode == 0 else "三级"))
	print("聚类簇数量: %d" % (max(labels) + 1))

	# 水平拼接域名与对应簇编号，写入wfile
	ret = np.hstack((res[:,:1], labels.reshape(-1, 1)))
	with io.open(wfile, "w") as f:
		for item in ret:
			f.write(str(list(item)) + "\n")

	print("KMeans聚类 完成！")


if __name__ == '__main__':
	initCppLibs()
	cluster_by_window("../../data/train_set/domainData.dat", 
		"../../data/train_set/domainData_test.dat", 10)
	get_feature_vector("../../data/train_set/domainData_test.dat".encode("utf-8"), 
		"../../data/feature_vector/feature_test.dat".encode("utf-8"))
	KMeansOfFeatureVector("../../data/feature_vector/feature_test.dat", 
		"../../data/feature_vector/feature_test_kmeans.dat")
	os.system("rm -f ../../data/feature_vector/feature_test.dat")
