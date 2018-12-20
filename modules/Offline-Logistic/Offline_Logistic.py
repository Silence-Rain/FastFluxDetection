#!coding=utf8

import sys
sys.path.append("../../")
import numpy as np
from utils.tools import *
from sklearn.linear_model import LogisticRegression

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

# 计算预测误差率
# 参数：预测标签结果，实际标签
def error_calc(predict, actual):
	total = len(predict)
	cnt = 0
	for index, item in enumerate(res):
		if item == actual[0][index]:
			cnt += 1
	return cnt / total


if __name__ == '__main__':
	# 训练数据集路径
	trainPath = "../../data/train_set/train_vector.dat"
	# 测试数据集路径
	predictPath = "../../data/train_set/vector.dat"

	# 读取数据集
	# 暂时使用[:,:-1]切掉最后一列的解析IP平均距离，训练数据有待完善
	train = read_data(trainPath)[:,:-1]
	predict = read_data(predictPath, 1)[:,:-1]
	# 建立Logistic模型
	model = LogisticRegression()
	# 0-1归一化处理
	train = normalize(train, 0)
	predict = normalize(predict)
	# # 打乱顺序
	# np.random.shuffle(train)

	# 训练模型
	# 参数1为测度矩阵，参数2为label数组
	model.fit(train[:,1:], train[:,:1].ravel())
	# 预测结果并输出
	res = model.predict(predict)
	print(res)
	