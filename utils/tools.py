#!coding=utf8

import time
import math
import requests
import IPy
import numpy as np

# 计算地理分布的香农熵
# 根据ip所属的国家和地区，计算分布概率
# 参数：{ip: (国家,地区,城市)}
# 返回值：香农熵（保留6位小数）
def shannon_entropy(geos):
	# 从地理归属字段中截取国家，地区部分
	raw = ["%s-%s" % (x[0],x[1]) for x in geos.values()]
	prob_raw = {}
	# 计算各个国家的频数
	for item in raw:
		if item in prob_raw:
			prob_raw[item] += 1
		else:
			prob_raw[item] = 1

	total = len(raw)
	# 计算各个国家分布概率
	prob = [x / total for x in prob_raw.values()]

	entropy = 0
	# 香农熵 = - SUM( P(x) * log2(P(x)) )
	for item in prob:
		entropy -= item * math.log2(item)

	return round(entropy, 6)

# 计算whois测度信息
# 参数：原始whois信息
# 返回值：{是否过期，信息完整的字段数}
def whois_analysis(info):
	ret = {"is_expire": 0, "item_complete": 0}
	cur = time.time()
	try:
		expire = time.mktime(time.strptime(info[-1].lower(), "%d-%b-%Y"))
		ret["is_expire"] = 0 if (cur < expire) else 1
	except:
		ret["is_expire"] = 1

	for item in info:
		if len(item) != 0:
			ret["item_complete"] += 1

	return ret

# 计算对端IP到解析IP的地理距离平均值
# # 参数：{ip: (国家,地区,城市)}
# 返回值：对端IP到解析IP的地理距离平均值（保留6位小数）
def opposite_location(ip_dict):
	proxy = {"http": "http://yunyang:yangyun123@202.112.23.167:8080"}
	cur_date = time.strftime("%Y-%m-%d", time.localtime())
	ret = {}
	# 取出解析IP列表
	ips = list(ip_dict.keys())
	# 遍历所有解析IP
	for ip in ips:
		opposite_dist = []
		target_pos = []
		ip_str = str(IPy.IP(ip))
		# 查询当天的IP活动流记录
		r = requests.get("http://211.65.197.210:8080/IPCIS/activityDatabase/"
			"?IpSets=%s:32&TableName=%s&Mode=1" % (ip_str, cur_date), proxies=proxy)
		res = r.json()[ip_str+":32"]
		for i in res:
			# 获得解析IP经纬度
			target_pos = i[0].split(" ")[-2:] if len(i) != 0 else target_pos
			# 获得对端IP经纬度，并计算距离
			for item in i[1:]:
				opposite_dist.append(haversine(target_pos, item.split(" ")[-2:]))
		# 记录每个对端IP的平均距离
		ret[ip] = round(sum(opposite_dist)/len(opposite_dist), 6)
	return round(sum(ret.values())/len(ret), 6)

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