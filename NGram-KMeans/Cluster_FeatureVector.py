#!coding=utf8

from ctypes import *
import numpy as numpy
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

if __name__ == '__main__':
	initCppLibs()
	r = "data/TrainSet/Malicious_more60".encode("utf-8")
	w = "data/t1".encode("utf-8")
	get_feature_vector(r, w)