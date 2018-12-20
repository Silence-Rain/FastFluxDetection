#!coding=utf8

import time
import math
import requests
import IPy
import numpy as np

# 计算地理分布的香农熵
# 根据ip所属的国家和地区，计算分布概率
# 参数：["国家-地区", ...]
# 返回值：香农熵（保留6位小数）
def shannon_entropy(geos):
	prob_raw = {}
	# 计算各个国家的频数
	for item in geos:
		if item in prob_raw:
			prob_raw[item] += 1
		else:
			prob_raw[item] = 1

	total = len(geos)
	# 计算各个国家分布概率
	prob = [x / total for x in prob_raw.values()]

	entropy = 0
	# 香农熵 = - SUM( P(x) * log2(P(x)) )
	for item in prob:
		entropy -= item * math.log2(item)

	return round(entropy, 6)

# 判断whois是否过期
# 参数：whois过期timestamp
# 返回值：是否过期
def whois_expire(ts):
	return 1 if ts < int(time.time()) else 0

# 计算解析IP到nsIP的地理距离平均值
# 参数：[[iplng1, iplat1], ...], [[nslng1, nslat1], ...]
# 返回值：解析IP到nsIP的地理距离平均值（保留6位小数）
def average_distance(ips, nss):
	dists = []
	for i in ips:
		for j in nss:
			dists.append(haversine(i, j))

	return round(sum(dists) / len(dists), 6)

# 计算地球上两个经纬度坐标点之间大圆距离
# 使用haversine公式
def haversine(pos1, pos2):
	# 将十进制度数转化为弧度
	lng1, lat1, lng2, lat2 = map(math.radians, 
		[float(pos1[0]), float(pos1[1]), float(pos2[0]), float(pos2[1])])
	# haversine公式
	dlng = lng2 - lng1
	dlat = lat2 - lat1
	a = math.sin(dlat / 2) ** 2 + math.cos(lat1) * math.cos(lat2) * math.sin(dlng / 2) ** 2
	c = 2 * math.asin(math.sqrt(a))
	r = 6371 		# 地球平均半径，单位为公里

	return round(c * r, 4)

# 0-1归一化
def zeroone(x, min, max):
	if x < min:
		return 0
	if x > max:
		return 1
	return (x - min) / (max - min)

# 使用0-1归一化，处理除label以外所有列的数据
# 参数：待处理数据，label列下标
# 返回值：0-1归一化之后的数据
def normalize(data, label_index=-1):
	data_size = len(data[0])
	data_max = [0 for x in range(data_size)]
	data_min = [0 for x in range(data_size)]

	for ind in range(0, data_size):
		if ind != label_index:
			data_max[ind] = np.max(data[:,ind:ind+1])
			data_min[ind] = np.min(data[:,ind:ind+1])
			for i in range(len(data)):
				data[i][ind] = zeroone(data[i][ind], data_min[ind], data_max[ind])

	return data