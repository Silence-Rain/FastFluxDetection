#!coding=utf8

from ctypes import *
import io
import numpy as numpy
# from sklearn.cluster import KMeans
# from utils import plot

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
	cnt = 0
	with io.open(rfile, "r") as f:
		for line in f.readlines():
			label = line.split(",")[0]
			if label not in ret_label:
				ret_label.append(label)
				ret.append(line)
		print(cnt)
	with io.open(rfile, "w") as f:
		for line in ret:
			f.write(line)

if __name__ == '__main__':
	# initCppLibs()
	# r1 = "data/TrainSet/Malicious_Test".encode("utf-8")
	w1 = "data/feature_test".encode("utf-8")
	# get_feature_vector(r1, w1)
	dereplicate(w1)