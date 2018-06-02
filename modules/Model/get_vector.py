#!coding=utf8

import time
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
			flabel.write(str(item)+"\n")
	print("raw data write complete!")

	for index, item in enumerate(raw):
		print("查询%d..." % index)

		try:
			ttl = model.get_ttl(item[1])
			whois = model.get_whois(item[1])
			ip = model.get_ip(item[1])
			ip_location = model.get_ip_location(ip)
		
			whois_info = whois_analysis(whois)
			ip_entropy = shannon_entropy(ip_location)

			ret.append([item[0], item[1], ttl, whois_info["is_expire"], 
				whois_info["item_complete"], ip_entropy])
		except:
			continue
			# ret.append([item[0], item[1]])

	with open(res, "w") as f:
		for item in ret:
			f.write(str(item)+"\n")

def add_flow_distance(rfile, wfile):
	dataset = []
	with open(rfile, "r") as f:
		for line in f.readlines():
			pass

def brute(labeled, res):
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
			
			# whois_info = whois_analysis(whois)
			# ip_entropy = shannon_entropy(ip_location)

			ret.append([item, ttl, whois, ip_location])
		except:
			# continue
			ret.append([item[0], item[1]])

	with open(res, "w") as f:
		for item in ret:
			f.write(str(item)+"\n")

if __name__ == '__main__':
	benignPath = "../../data/train_set/alexa_top10000.dat"
	botPath = "../../data/train_set/bots_domain.dat"
	labeledPath = "../../data/train_set/labeled_domain.dat"
	resPath = "../../data/train_set/vector.dat"

	# formatter(benignPath, botPath, labeledPath, resPath)
	brute(labeledPath, resPath)