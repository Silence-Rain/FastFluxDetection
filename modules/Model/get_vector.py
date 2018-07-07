#!coding=utf-8

import time
import sys
sys.path.append("../../")
# from model import DetailModel
from utils.tools import *

# model = DetailModel()

# 从benign，bot获取原始域名数据，添加label后写入labeled
# 每行格式：[0/1, 域名]
def add_label(benign, bot, labeled):
	raw = []
	with open(benign, "r") as fbenign:
		for line in fbenign.readlines()[:1000]:
			raw.append([0, line.strip()])
	with open(bot, "r") as fbot:
		for line in fbot.readlines()[:5513]:
			raw.append([1, line.strip()])
	with open(labeled, "w") as flabel:
		for item in raw:
			flabel.write(str(item)+"\n")
	print("label write complete!")

def get_raw_data(labeled, temp):
	raw = []
	ret = []
	with open(labeled, "r") as f:
		for line in f.readlines():
			raw.append(eval(line))

	for index, item in enumerate(raw):
		print("查询%d...%s" % (index, time.strftime('%Y-%m-%d %H:%M:%S')))

		try:
			ttl = model.get_ttl(item[1])
			whois = model.get_whois(item[1])
			ip = model.get_ip(item[1])
			ip_location = model.get_ip_location(ip)

			ret.append([item, ttl, whois, ip_location])
		except:
			ret.append([item])

	with open(temp, "w") as f:
		for item in ret:
			f.write(str(item)+"\n")

def vectorize(temp, res):
	raw = []
	ret = []
	with open(temp, "r") as f:
		for line in f.readlines():
			raw.append(eval(line))

	for item in raw:
		try:
			# 如果这条数据缺失“解析IP”字段，则直接跳过
			if len(item[3]) == 0:
				continue
			# ttl取平均值
			ttl_avr = round(sum(item[1])/len(item[1]),6)
			# 判断whois的完整性与是否过期
			whois_info = whois_analysis(item[2])
			# 计算解析IP地理分布熵
			ip_entropy = shannon_entropy(item[3])
			# 计算对端IP到解析IP的地理距离平均值
			opposite_dist_avr = 0 # opposite_location(item[3])
			ret.append([item[0][0], ttl_avr, whois_info["is_expire"], whois_info["item_complete"], 
				ip_entropy, opposite_dist_avr])
		except:
			# 如果原数据格式异常，则直接跳过
			continue

	with open(res, "w") as f:
		for item in ret:
			f.write(str(item)+"\n")


if __name__ == '__main__':
	benignPath = "../../data/train_set/alexa_top10000.dat"
	botPath = "../../data/train_set/bots_domain.dat"
	labeledPath = "../../data/train_set/labeled_domain.dat"
	tempPath = "../../data/train_set/temp_vector.dat"
	resPath = "../../data/train_set/vector.dat"

	add_label(benignPath, botPath, labeledPath)
	get_raw_data(labeledPath, tempPath)
	vectorize(tempPath, resPath)