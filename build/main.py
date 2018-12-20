import numpy as np
import random
import elm.tools
from elm.OS_ELM import OS_ELM

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
	# 隐层节点数
	hidden_neuron_num = 60
	# 输入层节点数
	input_neuron_num = 4
	# 建立OS-ELM
	elm = OS_ELM(hidden_neuron=hidden_neuron_num, input_neuron=input_neuron_num)

	# 训练数据集路径
	trainPath = "./data/alexa.vec"
	# 读取训练集
	train = read_data(trainPath, 1)
	# 0-1归一化处理
	train = tools.normalize(train, 0)
	# 打乱顺序
	np.random.shuffle(train)
	# 训练模型
	network = elm.fit_init(data=train)
	
	# # 测试数据集路径
	# predictPath = "./temp/test.vec"
	# predict = read_data(predictPath, 1)
	# predict = tools.normalize(predict)
	# # 预测结果并输出
	# res = network.predict(data=predict)
	# print(res)
