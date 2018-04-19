#!coding=utf8

import time
import ctypes
from ctypes import *
import Levenshtein
import numpy as np
from sklearn.cluster import DBSCAN
import plot

getPrimaryDomain = None

# 初始化C++接口调用
def initCppLibs():
	ll = ctypes.cdll.LoadLibrary
	lib = ll("./libPrimaryDomain.so")
	global getPrimaryDomain

	# 生成函数指针
	init = lib.init
	getPrimaryDomain = lib.getPrimaryDomain
	getPrimaryDomain.restype = c_char_p

	init()		# 接口内部初始化


# 从rfile中读取在window时间窗口内的记录，每行格式：domainName,ip,ttl,firstTime
# 聚合相同域名的不同ip，将ttl和firsttime取最小值
# 结果写入到wfile中，每行格式：[domainName, [ip1, ip2, ...], ttl, firstTime]
def clusterDomains(rfile, wfile, window):
	ret = [[""]]    			# 最终写入结果
	curTime = 1505115195 # int(time.time())	# 当前时间戳

	with open(rfile, "r") as f:
		res = f.readlines()
		lastptr = 0     # 上一条记录的指针

		# 按行读取
		for i in range(0, len(res)):
			arr = res[i].split(",")

			# 若当前记录的发现时间在window时间窗口内，记录下来
			if int(arr[-1]) >= curTime - window:
				temp = [arr[0], [int(arr[1])], int(arr[2]), int(arr[3])]     # 写入数据结构
				last = ret[lastptr]     # 上一条记录

				# 若当前记录的域名与上一条相同，则聚合
				if temp[0] == last[0]:
					last[1].append(temp[1][0])
					last[2] = temp[2] if (temp[2] < last[2]) else last[2]
					last[3] = temp[3] if (temp[3] < last[3]) else last[3]
				else:
					ret.append(temp)
					lastptr += 1

	ret = ret[1:]
	
	with open(wfile, "w") as f:
		for item in ret:
			f.write(str(item) + "\n")

# 获取rfile中所有域名，每行格式：[domainName, [ip1, ip2, ...], ttl, firstTime]
# 计算所有域名的二级三级域标签
# 写入到wfile中，每行格式：(domainName, 2ndDomainLabel, 3rdDomainLabel)
def get2dl3dl(rfile, wfile):
	ret = []

	with open(rfile, "r") as f:
		for line in f.readlines():
			name = eval(line)[0]	# 每行第一个字段是全域名
			
			pd = str(getPrimaryDomain(name))				# 主域名
			dl2 = pd.split(".")[0]							# 二级域标签
			dl3 = name[:-(len(pd) + 1)].split(".")[-1]		# 三级域标签
			
			ret.append((name, dl2, dl3))

	with open(wfile, "w") as f:
		for item in ret:
			f.write(str(item) + "\n")

# 获取rflie中所有域名及其二级，三级域标签，每行格式：(domainName, 2ndDomainLabel, 3rdDomainLabel)
# 计算所有域名的二级，三级域标签两两之间的编辑距离
# 结果写入到wfile中，输出格式(dn: domainName, dl: domainLabel, ld: LevenshteinDistance)：
# [dn0, (), (2dl's ld with dn1, 3dl's ld with dn1), (2dl's ld with dn2, 3dl's ld with dn2), ...]
# [dn1, (2dl's ld with dn0, 3dl's ld with dn0), (), (2dl's ld with dn1, 3dl's ld with dn1), ...]
# [dn2, (2dl's ld with dn0, 3dl's ld with dn0), (2dl's ld with dn1, 3dl's ld with dn1), (), ...]
def getLevenshteinDistOf2dl3dl(rfile, wfile):
	raw = []
	res = []

	with open(rfile, "r") as f:
		# 计算前100个
		for line in f.readlines()[:100]:
			raw.append(eval(line))

	# 两两计算编辑距离
	for i in raw:
		temp = [i[0]]
		for j in raw:
			# 不计算自身和自身的编辑距离，记为空元组
			if i[0] == j[0]:
				temp.append(())
			else:
				ld2 = Levenshtein.distance(i[1], j[1])
				ld3 = Levenshtein.distance(i[2], j[2])

				temp.append((ld2, ld3))

		res.append(temp)

	with open(wfile, "w") as f:
		for item in res:
			f.write(str(item) + "\n")

	print("Levenshtein Done!")

# 根据mode取值确定聚类对象。0:二级域标签，1:三级域标签
# 获取rfile中每个域名与其他所有域名标签之间的编辑距离。每行格式：[dn0, (), (2dl's ld with dn1, 3dl's ld with dn1), (2dl's ld with dn2, 3dl's ld with dn2), ...]
# 使用DBSCAN算法对编辑距离聚类
# 聚类结果写入wfile中。每行格式：[(域名对1), (域名对2), ...]
def dbscanOfLevenshteinDist(rfile, wfile, mode):
	raw = []

	with open(rfile, "r") as f:
		lines = f.readlines()

		# 只取出n*n编辑距离矩阵的上三角部分（不含对角线），放入raw
		# 得到的数据格式：[[dn0 with dn1, dn0 with dn2, ...], [dn1 with dn2, ...], ...]
		for i in range(len(lines) - 1):
			dat = eval(lines[i])[1:]
			temp = []

			for j in range(i + 1, len(lines)):
				temp.append(dat[j][mode])	# 根据mode读入对应标签的编辑距离

			raw.append(temp)

	# 关联编辑距离对和其域名下标
	# 得到的数据格式：[[i, j, dni with dnj], ...]
	# 域名下标可在domainData_clustered.dat文件中找到映射
	res = []
	for i in range(len(raw)):
		for j in range(len(raw)-i):
			res.append([i, i+1+j, raw[i][j]])
	res = np.array(res)

	clst = DBSCAN(eps=0.5, min_samples=10)
	labels = clst.fit_predict(res[:,2].reshape(-1, 1))
	print("Cluster types: %d" % (max(labels)+2))	# 要加上-1，0两个类型
	print("Core samples' num: %d" % len(clst.core_sample_indices_))

	# # 作出聚类后数据的3D散点图
	# plot.plot_3d_scatter(res, labels)

	# 按照DBSCAN的聚类结果，将编辑距离对分类。结果写入wfile
	ret = [[] for x in range(max(labels)+2)]
	for i in range(len(labels)):
		ret[labels[i]].append(tuple(res[i][:-1]))

	with open(wfile, "w") as f:
		for item in ret:
			f.write(str(item) + "\n")


if __name__ == '__main__':
	# initCppLibs()
	
	# clusterDomains("data/domainData_Test.dat", "data/domainData_clustered.dat", 1)
	# get2dl3dl("data/domainData_clustered.dat", "data/domain_2dl3dl.dat")
	# getLevenshteinDistOf2dl3dl("data/domain_2dl3dl.dat", "data/domain_2dl3dl_levenshteinDist_1.dat")
	dbscanOfLevenshteinDist("data/domain_2dl3dl_levenshteinDist_1.dat", "data/domain_2dl_dbscan.dat", 0)

