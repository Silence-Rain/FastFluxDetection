#!coding=utf8

import time

# 计算地理分布的香农熵
def shannon_entropy(location):
	return 0

# 计算whois测度信息
# 参数：原始whois信息
# 返回值：{是否过期，信息完整的字段数}
def whois_analysis(info):
	ret = {"is_expire": 0, "item_complete": 0}
	cur = time.time()
	expire = time.mktime(time.strptime(info[-1].lower(), "%d-%b-%Y"))
	ret.is_expire = 0 if (expire < cur) else 1

	for item in info:
		if len(item) != 0:
			ret.item_complete += 1

	return ret