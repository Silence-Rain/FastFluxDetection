#!coding=utf8

import numpy as np
from sklearn.linear_model import LogisticRegression

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
def error_calc(predict, actual):
	total = len(predict)
	cnt = 0
	for index, item in enumerate(res):
		if item == actual[0][index]:
			cnt += 1
	return cnt / total


if __name__ == '__main__':
	model = LogisticRegression()
	# init_set = read_data("../../data/train_set/vector.dat")
	init_set = np.loadtxt(open("../../data/segment_test1.csv", "r"), 
		delimiter=",", skiprows=1)
	model.fit(init_set[:600,1:], init_set[:600,:1].ravel())

	res = model.predict(init_set[600:,1:])
	actual = init_set[600:,:1].reshape(1, -1)
	print(error_calc(res, actual))
	