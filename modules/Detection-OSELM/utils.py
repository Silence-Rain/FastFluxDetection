#!coding=utf8

import time

# 转换dat文件为带label的域名数组
def convert2list(benign, bot):
	res = []
	with open(benign, "r") as fbenign:
		for line in fbenign.readlines()[:10]:
			res.append([0, line.strip()])
	with open(bot, "r") as fbot:
		for line in fbot.readlines()[:10]:
			res.append([1, line.strip()])

	return res

# 计算地理分布的香农熵
def shannon_entropy(location):
	return 0

# 计算whois测度信息
# 参数：原始whois信息
# 返回值：{是否过期，信息完整的字段数}
def whois_analysis(info):
	ret = {"is_expire": False, "item_complete": 0}

	cur = time.time()
	expire = time.mktime(time.strptime(info[-1].lower(), "%d-%b-%Y"))
	ret.is_expire = expire < cur

	for item in info:
		if len(item) != 0:
			ret.item_complete += 1

	return ret