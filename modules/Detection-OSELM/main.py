#!coding=utf8

import sys
sys.path.append("../../")
import numpy as np
from OS_ELM import OS_ELM

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
	elm = OS_ELM(hidden_neuron=50, input_neuron=4)
	res = read_data("../../data/train_set/vector.dat")

	network = elm.fit_init(data=res)
	network.fit_train(data=res)
