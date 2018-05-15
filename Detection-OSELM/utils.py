#!coding=utf8

import time

def shannon_entropy():
	pass

def whois_analysis(info):
	ret = {"is_expire": False, "item_complete": 0}

	cur = time.time()
	expire = time.mktime(time.strptime(info[-1].lower(), "%d-%b-%Y"))
	ret.is_expire = expire < cur

	for item in info:
		if len(item) != 0:
			ret.item_complete += 1

	return ret