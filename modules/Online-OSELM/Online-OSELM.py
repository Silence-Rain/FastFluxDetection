#!coding=utf8

import sys
sys.path.append("../../")
import numpy as np
import random
from OS_ELM import OS_ELM
from utils.tools import *

# 从文件中读取域名特征向量
# ignore: 忽略前n列
def read_data(path, ignore=0):
	res = []
	with open(path, "r") as f:
		for line in f.readlines():
			temp = eval(line)[ignore:]
			res.append([float(i) for i in temp])

	return np.array(res)

# 数据写入文件
def write_data(data, path):
	with open(path, "w") as f:
		for item in data:
			f.write(str(item)+"\n")


if __name__ == '__main__':
	# 训练数据集路径
	trainPath = "../../data/train_set/train_vector.dat"
	# 测试数据集路径
	predictPath = "../../data/train_set/vector.dat"
	# 隐层节点数
	hidden_neuron_num = 60
	# 输入层节点数
	input_neuron_num = 4

	# 读取数据集
	# 暂时使用[:,:-1]切掉最后一列的解析IP平均距离，训练数据有待完善
	train = read_data(trainPath)[:,:-1]
	predict = read_data(predictPath, 1)[:,:-1]
	# 建立OS-ELM，输入节点5个，隐层节点60个
	elm = OS_ELM(hidden_neuron=hidden_neuron_num, input_neuron=input_neuron_num)
	# 0-1归一化处理
	train = normalize(train, 0)
	predict = normalize(predict)
	# # 打乱顺序
	# np.random.shuffle(train)

	# 训练模型
	network = elm.fit_init(data=train)
	# 预测结果并输出
	res = network.predict(data=predict)
	print(res)
