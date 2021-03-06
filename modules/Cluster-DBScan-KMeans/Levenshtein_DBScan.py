#!coding=utf8

import time
import sys
sys.path.append("../../")
from ctypes import *
import Levenshtein
import numpy as np
from sklearn.cluster import DBSCAN
from utils import plot

getPrimaryDomain = None
domain_label_map = []		# 域名-下标（行数）映射

# 初始化C++接口调用
def initCppLibs():
	ll = cdll.LoadLibrary
	lib = ll("../../lib/libPrimaryDomain.so")
	global getPrimaryDomain
	# 生成函数指针
	init = lib.init
	getPrimaryDomain = lib.getPrimaryDomain
	getPrimaryDomain.argtypes = [c_char_p]		# 设置参数格式
	getPrimaryDomain.restype = c_char_p			# 设置返回值格式
	init()		# 接口内部初始化

	print("动态库libPrimaryDomain.so已加载！")

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

# 获取rfile中所有域名，每行格式：[domainName, [ip1, ip2, ...], ttl, firstTime]
# 						或：每行一个domainName
# 计算所有域名的二级三级域标签
# 写入到wfile中，每行格式：(domainName, 2ndDomainLabel, 3rdDomainLabel)
def get2dl3dl(rfile, wfile):
	with open(rfile, "r") as f:
		for line in f.readlines():
			# 每行一个domainName
			name = line.strip()
			name_byte = name.encode("utf-8")
			# # 每行第一个字段是domainName
			# name = eval(line)[0]	
			# 读取到空行，继续循环
			if len(name_byte) == 0:
				continue

			pd = getPrimaryDomain(name_byte).decode()		# 主域名
			dl2 = pd.split(".")[0]							# 二级域标签
			dl3 = name[:-(len(pd) + 1)].split(".")[-1]		# 三级域标签
			domain_label_map.append((name, dl2, dl3))

	with open(wfile, "w") as f:
		for item in domain_label_map:
			f.write(str(item) + "\n")

	print("获取域名二级，三级域标签 完成！")

# 获取rflie中所有域名及其二级，三级域标签，每行格式：(domainName, 2ndDomainLabel, 3rdDomainLabel)
# 计算所有域名的二级，三级域标签两两之间的编辑距离
# 结果写入到wfile中，输出格式(dn: domainName, dl: domainLabel, ld: LevenshteinDistance)：
# [(), (2dl's ld dn0dn1, 3dl's ld dn0dn1), (2dl's ld dn0dn2, 3dl's ld dn0dn2), ...]
# [(2dl's ld dn1dn0, 3dl's ld dn1dn0), (), (2dl's ld dn1dn2, 3dl's ld dn1dn2), ...]
# [(2dl's ld dn2dn0, 3dl's ld dn2dn0), (2dl's ld dn2dn1, 3dl's ld dn2dn1), (), ...]
# 域名与下标映射 => domain_label_map
def getLevenshteinDistOf2dl3dl(rfile, wfile):
	print("计算域名标签两两之间编辑距离 开始...")

	raw = []
	res = []
	with open(rfile, "r") as f:
		for line in f.readlines():
			raw.append(eval(line))

	# 两两计算编辑距离
	for i in range(len(raw)):
		temp = []
		for j in range(len(raw)):
			# 不计算自身和自身的编辑距离，记为空元组
			if i == j:
				temp.append(())
			elif i < j:
				ld2 = Levenshtein.distance(raw[i][1], raw[j][1])
				ld3 = Levenshtein.distance(raw[i][2], raw[j][2])

				temp.append((ld2, ld3))
			else:
				temp.append(res[j][i])
		res.append(temp)

	with open(wfile, "w") as f:
		for item in res:
			f.write(str(item) + "\n")

	print("计算域名标签两两之间编辑距离 完成！")

# 根据mode取值确定聚类对象。0:二级域标签，1:三级域标签
# 获取rfile中域名两两之间的编辑距离矩阵
# 每行格式：[(), (2dl's ld dn0dn1, 3dl's ld dn0dn1), (2dl's ld dn0dn2, 3dl's ld dn0dn2), ...]
# 使用DBScan算法对编辑距离聚类
# 聚类结果写入wfile中。每行格式：[域名, 聚类簇编号]
def dbscanOfLevenshteinDist(rfile, wfile, mode=1):
	print("DBScan聚类 开始...")

	raw = []
	ret = []
	# 读取编辑距离矩阵
	with open(rfile, "r") as f:
		lines = f.readlines()
		for line in lines:
			temp = []
			for item in eval(line):
				if len(item) != 0:
					temp.append(item[mode])		# 根据mode读入对应标签的编辑距离
				else:
					temp.append(0)
			raw.append(temp)

	# 用DBScan算法对编辑距离进行聚类
	# 直接使用编辑距离作为两数据点之间的距离
	# 使用参数：
	# 邻域：3，簇内最小样本数：3
	clst = DBSCAN(eps=3, metric="precomputed", min_samples=3)
	labels = clst.fit_predict(np.array(raw))
	print("Current label: %s" % ("secondary" if mode == 0 else "ternary"))
	print("Cluster types: %d" % (max(labels) + 2))		# 要加上-1，0两个类型
	print("Core samples' num: %d" % len(clst.core_sample_indices_))

	# # 作出聚类后数据的散点图
	# plot.plot_scatter(np.array(raw), labels)

	# 根据domain_label_map中，域名和下标的映射，将结果写入文件
	for index, item in enumerate(domain_label_map):
		ret.append([item[0], labels[index]])

	with open(wfile, "w") as f:
		for item in ret:
			f.write(str(item) + "\n")

	print("DBScan聚类 完成！")


if __name__ == '__main__':
	initCppLibs()
	cluster_by_window("../../data/train_set/domainData.dat", 
		"../../data/train_set/domainData_test.dat", 10)
	get2dl3dl("../../data/train_set/domainData_test.dat", 
	 	"../../data/levenshtein_distance/2dl3dl_test.dat")
	getLevenshteinDistOf2dl3dl("../../data/levenshtein_distance/2dl3dl_test.dat", 
		"../../data/levenshtein_distance/levenshtein_test.dat")
	dbscanOfLevenshteinDist("../../data/levenshtein_distance/levenshtein_test.dat", 
		"../../data/levenshtein_distance/levenshtein_dbscan_test.dat", 0)
