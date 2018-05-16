#!coding=utf8

import sys
sys.path.append("../../")
import numpy as np
from model import DetailModel
from utils import *
from OS_ELM import OS_ELM

if __name__ == '__main__':
	model = DetailModel()
	elm = OS_ELM(hidden_neuron=180, input_neuron=19)

	benignPath = "../../data/alexa_top10000.dat"
	botPath = "../../data/bots_domain.dat"
	res = convert2list(benignPath, botPath)

	for item in res:
		ttl = model.get_ttl(item[1])
		whois = model.get_whois(item[1])
		ip = model.get_ip(item[1])
		ip_location = model.get_ip_location(item[1])
		whois_feat = whois_analysis(whois)
		ip_entropy = shannon_entropy(ip_location)

		item.append(ttl, whois_feat["is_expire"], whois_feat["item_complete"], ip_entropy)

	res = np.array(res)
	network = elm.fit_init(data=res)
	# network.fit_train(data=res)