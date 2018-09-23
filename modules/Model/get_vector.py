#!coding=utf-8

import time
import sys
sys.path.append("../../")
from model import DetailModel
from utils.tools import *

model = DetailModel()

# 获取训练集
# 从benign，bot获取原始域名数据，添加label后写入labeled
# 每行格式：[0/1, 域名]
def get_train_set_by_label(benign, bot, labeled):
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

# 获取测试集
# 根据时间窗口取得测试集聚合IP后的结果
# 每行格式：[域名，[ip1, ip2, ...]，TTL，timestamp]
def get_test_set_by_window(test, test_res, window):
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

# 获取原始测度
def get_raw_measure(path, temp):
	raw = []
	ret = []
	with open(path, "r") as f:
		for line in f.readlines():
			raw.append(eval(line))

	for index, item in enumerate(raw):
		print("查询%d...%s" % (index, time.strftime('%Y-%m-%d %H:%M:%S')))
		try:
			ttl = item[2]
			whois = model.get_whois(item[0])
			ip = item[1]
			ip_location = model.get_ip_location(ip)

			ret.append([item[0], ttl, whois, ip_location])
		except:
			ret.append([item[0]])

	with open(temp, "w") as f:
		for item in ret:
			f.write(str(item)+"\n")

# 获取计算后的特征向量
def vectorize(temp, res):
	raw = []
	ret = []
	with open(temp, "r") as f:
		for line in f.readlines():
			raw.append(eval(line))

	for item in raw:
		try:
			# 判断whois的完整性与是否过期
			whois_info = whois_analysis(item[2])
			# 计算解析IP地理分布熵
			ip_entropy = shannon_entropy(item[3])
			# 计算对端IP到解析IP的地理距离平均值
			opposite_dist_avr = opposite_location(item[3])
			ret.append([item[0][0], item[1], whois_info["is_expire"], whois_info["item_complete"], 
				ip_entropy, opposite_dist_avr])
		except:
			# 如果原数据格式异常，则直接跳过
			continue

	with open(res, "w") as f:
		for item in ret:
			f.write(str(item)+"\n")


if __name__ == '__main__':
	# test: 测试，train:训练
	flag = "test"

	if flag == "train":
		benignPath = "../../data/train_set/alexa_top10000.dat"
		botPath = "../../data/train_set/bots_domain.dat"
		labeledPath = "../../data/train_set/labeled_domain.dat"
		get_train_set_by_label(benignPath, botPath, labeledPath)
	else:
		testPath = "../../data/train_set/domainData_Test.dat"
		testResPath = "../../data/train_set/domainData_test_res.dat"
		get_test_set_by_window("", "test", 5)
	
	tempPath = "../../data/train_set/temp_vector.dat"
	resPath = "../../data/train_set/vector.dat"
	get_raw_data(labeledPath, tempPath)
	vectorize(tempPath, resPath)
