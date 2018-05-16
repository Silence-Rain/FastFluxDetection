#!coding=utf8

import sys
sys.path.append("../../")
from ctypes import *
import io
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

# 获取rfile中C++接口所得域名特征向量结果
# 去除其中重复项，写回
def dereplicate(rfile):
	ret = []			# 最终结果
	ret_label = []		# 域名集合
	with io.open(rfile, "r") as f:
		for line in f.readlines():
			label = line.split(",")[0]

			# 当前域名不在已有集合中，特征向量加入最终结果
			if label not in ret_label:
				ret_label.append(label)
				ret.append(line)

	with io.open(rfile, "w") as f:
		for line in ret:
			f.write(line)

	print("特征向量去重 完成！")

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
	get_feature_vector("../../data/train_set/malicious_10000.dat".encode("utf-8"), 
		"../../data/feature_vector/feature_test.dat".encode("utf-8"))
	dereplicate("../../data/feature_vector/feature_test.dat")
	KMeansOfFeatureVector("../../data/feature_vector/feature_test.dat", 
		"../../data/feature_vector/feature_test_kmeans.dat")