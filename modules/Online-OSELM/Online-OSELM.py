#!coding=utf8

import sys
sys.path.append("../../")
import numpy as np
import random
from OS_ELM import OS_ELM
from utils.tools import *

# 从文件中读取域名特征向量
def read_data(path):
	res = []
	with open(path, "r") as f:
		for line in f.readlines():
			res.append(eval(line))

	return np.array(res)

# 数据写入文件
def write_data(data, path):
	with open(path, "w") as f:
		for item in data:
			f.write(str(item)+"\n")


if __name__ == '__main__':
	# 建立OS-ELM，输入节点5个，隐层节点60个
	elm = OS_ELM(hidden_neuron=60, input_neuron=5)
	res = read_data("../../data/train_set/vector.dat")
	# 0-1归一化处理
	res = normalize(res)
	# 打乱顺序
	np.random.shuffle(res)
	# 后1000个用来预测，前面的用来训练
	network = elm.fit_init(data=res[:-1000])
	network.predict(data=res[-1000:, 1:])
