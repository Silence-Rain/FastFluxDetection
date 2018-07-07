#!coding=utf8

import numpy as np
from utils.tools import *
from sklearn.linear_model import LogisticRegression

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
	model = LogisticRegression()
	init_set = read_data("../../data/train_set/vector.dat")
	# 0-1归一化处理
	init_set = normalize(init_set)
	# 打乱顺序
	np.random.shuffle(init_set)
	# 训练模型
	# 参数1为测度矩阵，参数2为label数组
	# 后1000个用于预测，前面的用来训练
	model.fit(init_set[:-1000,1:], init_set[:-1000,:1].ravel())
	# 预测结果为1维数组
	res = model.predict(init_set[-1000:,1:])
	actual = init_set[-1000:,:1].reshape(1, -1)
	print("准确率为：%d" % error_calc(res, actual))
	