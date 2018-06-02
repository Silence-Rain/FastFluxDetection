#!coding=utf8

import time
import math

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

