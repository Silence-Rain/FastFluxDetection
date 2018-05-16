#!coding=utf8

import sys
sys.path.append("../../")
import numpy as np
from model import DetailModel
from utils.tools import *
from OS_ELM import OS_ELM

# 原始数据格式转换
# 转换为带label的域名数组
def formatter(benign, bot):
	raw = []
	ret = []
	with open(benign, "r") as fbenign:
		for line in fbenign.readlines()[:1000]:
			raw.append([0, line.strip()])
	with open(bot, "r") as fbot:
		for line in fbot.readlines():
			raw.append([1, line.strip()])

	for item in raw:
		# ttl = model.get_ttl(item[1])
		# whois = model.get_whois(item[1])
		# ip = model.get_ip(item[1])
		# ip_location = model.get_ip_location(item[1])
		# whois_feat = whois_analysis(whois)
		# ip_entropy = shannon_entropy(ip_location)

		# ret.append(item[0], ttl, whois_feat["is_expire"], 
		# 	whois_feat["item_complete"], ip_entropy)
		
		if item[0] == 0:
			ret.append([0,0.5,0.2,0.3,0.4,0.2])
		else:
			ret.append([1,1,0.8,1,1,1])
	
	return np.array(ret)

if __name__ == '__main__':
	model = DetailModel()
	elm = OS_ELM(hidden_neuron=50, input_neuron=4)
	benignPath = "../../data/train_set/alexa_top10000.dat"
	botPath = "../../data/train_set/bots_domain.dat"

	res = formatter(benignPath, botPath)
	network = elm.fit_init(data=res)
	network.fit_train(data=res)
