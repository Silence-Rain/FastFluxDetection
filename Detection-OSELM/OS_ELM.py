#!coding:UTF-8

import numpy as np

class OS_ELM(object):
	def __init__(self, hidden_neuron, input_neuron):
		self.num_hidden_neurons = hidden_neuron
		self.num_input_neurons = input_neuron

		self.Iw = np.mat(np.random.rand(self.num_hidden_neurons, self.num_input_neurons) * 2 - 1)
		self.bias = np.mat(np.random.rand(1, self.num_hidden_neurons))
		self.M = None
		self.beta = None

	def sig(self, tData, Iw, bias, num):
		'''
		tData:样本矩阵：样本数*特征数
		Iw:输入层到第一个隐含层的权重：隐含层神经元数*特整数
		bias:偏置1*隐含神经元个数
		'''
		v = tData * Iw.T	#样本数*隐含神经元个数
		bias_1 = np.ones((num, 1)) * bias
		v = v + bias_1
		H = 1./(1 + np.exp(-v))
		return H

	def fit_init(self, data):
		label = []
		matrix = []
		# 处理训练样本
		for row in data:
			temp = []
			label.append(int(row[1]))
			# 处理特征
			for item in row[2:]:
				temp.append(item)
			matrix.append(temp)
		
		# 开始训练
		p0 = np.mat(matrix)
		T0 = np.zeros((len(matrix), 7))
		# 处理样本标签
		for index, item in enumerate(label):
			T0[index][item - 1] = 1
		T0 = T0 * 2 - 1
		# 样本数*隐含神经元个数
		H0 = self.sig(p0, self.Iw, self.bias, len(matrix))
		self.M = (H0.T * H0).I
		self.beta = self.M * H0.T * T0

		return self

	def fit_train(self, data):
		for row in data:
			Tn = np.zeros((1, 7))
			# 处理样本标签
			b = int(row[1])
			Tn[0][b - 1] = 1
			Tn = Tn * 2 - 1
			# 处理特征
			matrix = []
			for item in row[2:]:
				matrix.append(item)
			pn = np.mat(matrix)
			H = self.sig(pn, self.Iw, self.bias, 1)
			self.M = self.M - self.M * H.T * (np.eye(1,1) + H * self.M * H.T).I * H * self.M
			self.beta = self.beta + self.M * H.T * (Tn - H * self.beta)

		self.error_calc(data)

		return self

	def predict(self, data):
		ret = []
		for row in data:
			# 处理特征
			matrix = []
			for item in row[2:]:
				matrix.append(item)
			p = np.mat(matrix)
			HTrain = self.sig(p, self.Iw, self.bias, 1)
			Y = HTrain * self.beta
			# 判断
			ret.append(argmax(Y) + 1)

		return np.array(ret).reshape(-1, 1)

	def error_calc(self, data):
		# 计算训练误差
		correct = 0
		sum = 0
		for row in data:
			# 处理特征
			matrix = []
			for item in row[2:]:
				matrix.append(item)
			p = np.mat(matrix)
			HTrain = self.sig(p, self.Iw, self.bias, 1)
			Y = HTrain * self.beta
			# 判断
			if np.argmax(Y) + 1 == int(row[1]):
				correct += 1
			sum += 1
		print("训练准确性为：%f" % (correct / sum))

if __name__ == '__main__':
	raw = np.loadtxt(open("./segment_test.csv", "r"), delimiter=",", skiprows=1)
	elm = OS_ELM(hidden_neuron=180, input_neuron=19)
	network = elm.fit_init(data=raw)
	network.fit_train(data=raw)
