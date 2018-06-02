#!coding=utf8

import time
import math
import requests
import IPy

# 计算地理分布的香农熵
# 根据ip所属的国家和地区，计算分布概率
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

# 计算对端IP到解析IP的地理距离
def opposite_location(ips):
	proxy = {"http": "http://yunyang:yangyun123@202.112.23.167:8080"}
	cur_date = time.strftime("%Y-%m-%d", time.localtime())
	ret = {}
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
				# opposite_dist.append(item.split("$")[-2])
		ret[ip] = opposite_dist
	return ret

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

if __name__ == '__main__':
	print(opposite_location([3544301847,3544302017]))

