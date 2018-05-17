#!coding=utf8

import sys
sys.path.append("../../")
from model import DetailModel
from utils.tools import *

model = DetailModel()

def formatter(benign, bot, labeled, res):
	raw = []
	ret = []
	with open(benign, "r") as fbenign:
		for line in fbenign.readlines()[:1000]:
			raw.append([0, line.strip()])
	with open(bot, "r") as fbot:
		for line in fbot.readlines()[:500]:
			raw.append([1, line.strip()])
	with open(labeled, "w") as flabel:
		for item in raw:
			f.write(str(item)+"\n")

	for index, item in enumerate(raw):
		print("查询%d..." % index)
		ttl = model.get_ttl(item[1])
		whois = model.get_whois(item[1])
		ip = model.get_ip(item[1])
		ip_location = model.get_ip_location(ip)
		
		whois_info = whois_analysis(whois)
		ip_entropy = shannon_entropy(ip_location)

		ret.append([item[0], ttl, whois_info["is_expire"], 
			whois_info["item_complete"], ip_entropy])

	with open(res, "w") as f:
		for item in ret:
			f.write(str(item)+"\n")


if __name__ == '__main__':
	benignPath = "../../data/train_set/alexa_top10000.dat"
	botPath = "../../data/train_set/bots_domain.dat"
	labeledPath = "../../data/train_set/labeled_domain.dat"
	resPath = "../../data/train_set/vector.dat"

	formatter(benignPath, botPath, labeledPath, resPath)