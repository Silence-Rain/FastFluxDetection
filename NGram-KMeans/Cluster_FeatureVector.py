#!coding=utf8

from ctypes import *
import io
import numpy as np
from sklearn.cluster import KMeans
from utils import plot

get_feature_vector = None

# 初始化C++接口调用
def initCppLibs():
	ll = cdll.LoadLibrary
	lib = ll("lib/libFeatureVector.so")
	global get_feature_vector

	# 生成函数指针
	init = lib.init
	get_feature_vector = lib.getFeatureVector
	get_feature_vector.argtypes = [c_char_p, c_char_p]
	get_feature_vector.restype = None

	init()		# 接口内部初始化

# C++接口所得结果去重
def dereplicate(rfile):
	ret = []
	ret_label = []
	with io.open(rfile, "r") as f:
		for line in f.readlines():
			label = line.split(",")[0]
			if label not in ret_label:
				ret_label.append(label)
				ret.append(line)
	with io.open(rfile, "w") as f:
		for line in ret:
			f.write(line)

def KMeansOfFeatureVector(rfile, wfile, mode=0):
	raw = []
	with io.open(rfile, "r") as f:
		for line in f.readlines():
			arr = line.split(",")
			temp = [arr[0]]

			if mode == 0:
				inds = [1,2,3,7,8,9,13,15,17]
				for i in inds:
					temp.append(arr[i])
			else:
				inds = [4,5,6,10,11,12,14,16,18]
				for i in inds:
					temp.append(arr[i])

			raw.append(temp)

	res = np.array(raw)
	clst = KMeans(n_clusters=10, random_state=0)
	labels = clst.fit_predict(res[:,1:])
	print("Current label: %s" % ("secondary" if mode == 0 else "ternary"))
	print("Cluster types: %d" % (max(labels) + 1))

	ret = np.hstack((res[:,:1], labels.reshape(-1, 1)))
	with io.open(wfile, "w") as f:
		for item in ret:
			f.write(str(list(item)) + "\n")


if __name__ == '__main__':
	# initCppLibs()
	# raw = "data/TrainSet/Malicious_Test".encode("utf-8")
	# fv_raw = "data/feature_test".encode("utf-8")
	# get_feature_vector(raw, fv_raw)
	# dereplicate(fv_raw)
	KMeansOfFeatureVector("data/feature_test", "data/feature_test_kmeans")