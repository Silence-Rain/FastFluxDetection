#!coding:UTF-8

import numpy as np

# 在线顺序极限学习机
# 构造参数：隐层节点数，输入节点数
class OS_ELM(object):
	def __init__(self, hidden_neuron, input_neuron):
		self.num_hidden_neurons = hidden_neuron
		self.num_input_neurons = input_neuron

		self.Iw = np.mat(np.random.rand(self.num_hidden_neurons, self.num_input_neurons) * 2 - 1)
		self.bias = np.mat(np.random.rand(1, self.num_hidden_neurons))
		self.M = None
		self.beta = None

	# 激活函数
	# 参数：tData: 样本矩阵
	#	Iw: 输入层权重
	#	bias: 隐层单元偏置
	# 返回值：隐层输出矩阵
	def sig(self, tData, Iw, bias):
		#样本数*隐含神经元个数
		v = tData * Iw.T
		bias_1 = np.ones((len(tData), 1)) * bias
		v = v + bias_1
		H = 1./(1 + np.exp(-v))
		return H

	# 使用初始数据训练网络
	# 参数：初始训练数据（np.array）
	# 返回值：训练后的网络
	def fit_init(self, data):
		label = []
		matrix = []
		for row in data:
			# 记录样本label
			temp = []
			label.append(int(row[0]))
			# 获取特征数据
			for item in row[1:]:
				temp.append(item)
			matrix.append(temp)
		
		p0 = np.mat(matrix)
		T0 = np.zeros((len(matrix), 7))
		# 处理样本标签
		for index, item in enumerate(label):
			T0[index][item - 1] = 1
		T0 = T0 * 2 - 1
		# 计算隐层输出矩阵
		H0 = self.sig(p0, self.Iw, self.bias)
		self.M = (H0.T * H0).I
		# 计算输出权重
		self.beta = self.M * H0.T * T0

		self.error_calc(data)

		return self

	# 使用在线数据更新网络
	# 参数：在线训练数据（np.array）
	# 返回值：更新后的网络
	def fit_train(self, data):
		# 逐条使用数据，对网络进行更新
		for row in data:
			Tn = np.zeros((1, 7))
			# 处理样本标签
			b = int(row[0])
			Tn[0][b - 1] = 1
			Tn = Tn * 2 - 1
			# 获取特征数据
			matrix = []
			for item in row[1:]:
				matrix.append(item)
			pn = np.mat(matrix)
			# 更新隐层输出矩阵
			H = self.sig(pn, self.Iw, self.bias)
			self.M = self.M - self.M * H.T * (np.eye(1,1) + H * self.M * H.T).I * H * self.M
			# 更新输出权重
			self.beta = self.beta + self.M * H.T * (Tn - H * self.beta)

		self.error_calc(data)

		return self

	# 使用现有模型对数据分类
	# 参数：需要分类的数据（np.array）
	# 返回值：添加label列的数据
	def predict(self, data):
		res = []
		for row in data:
			# 处理特征
			matrix = []
			for item in row[1:]:
				matrix.append(item)
			p = np.mat(matrix)
			HTrain = self.sig(p, self.Iw, self.bias)
			Y = HTrain * self.beta
			# 返回预测label
			res.append(argmax(Y) + 1)
		res = np.array(res)
		ret = np.hstack((res.reshape(-1, 1), data))

		return ret

	# 计算训练的误差值
	# 参数：训练数据
	def error_calc(self, data):
		correct = 0
		sum = 0
		for row in data:
			# 处理特征
			matrix = []
			for item in row[1:]:
				matrix.append(item)
			p = np.mat(matrix)
			HTrain = self.sig(p, self.Iw, self.bias)
			Y = HTrain * self.beta
			# 若预测结果和实际结果相同则计数
			if np.argmax(Y) + 1 == int(row[0]):
				correct += 1
			sum += 1
		print("训练准确性为：%f" % (correct / sum))

# if __name__ == '__main__':
# 	raw = np.loadtxt(open("./segment_test.csv", "r"), delimiter=",", skiprows=1)
# 	elm = OS_ELM(hidden_neuron=180, input_neuron=19)
# 	network = elm.fit_init(data=raw)
# 	network.fit_train(data=raw)
