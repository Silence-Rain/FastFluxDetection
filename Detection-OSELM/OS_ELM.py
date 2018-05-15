#!coding:UTF-8
from csv import DictReader
from math import exp
import random
from numpy import *

class OS_ELM(object):
	def __init__(self, hidden_neuron, input_neuron, init_size):
		self.num_hidden_neurons = hidden_neuron
		self.num_input_neurons = input_neuron
		self.init_trainset_size = init_size

		self.Iw = mat(random.rand(self.num_hidden_neurons, self.num_input_neurons) * 2 - 1)
		self.bias = mat(random.rand(1, self.num_hidden_neurons))
		self.M = None
		self.beta = None

	def sig(self, tData, Iw, bias, num):
		'''
		tData:样本矩阵：样本数*特征数
		Iw:输入层到第一个隐含层的权重：隐含层神经元数*特整数
		bias:偏置1*隐含神经元个数
		'''
		v = tData * Iw.T	#样本数*隐含神经元个数
		bias_1 = ones((num, 1)) * bias
		v = v + bias_1
		H = 1./(1 + exp(-v))
		return H

	def fit_init(self, dataPath):
		label = []
		data = []
		# 处理训练样本
		for t, row in enumerate(DictReader(open(dataPath))):
			Id = row['Id']
			del row['Id']
			temp = []
			# 处理是否被点击
			y = int(float(row['Label']))
			del row['Label']
			label.append(y)
			# 处理特征
			for key in row:
				value = float(row[key])
				temp.append(value)
			
			data.append(temp)
		
			if t == self.init_trainset_size - 1:	
				# 开始训练
				p0 = mat(data)
				T0 = zeros((self.init_trainset_size, 7))
				# 处理样本标签
				for i in range(0, self.init_trainset_size):
					a = label[i]
					T0[i][a - 1] = 1
				
				T0 = T0 * 2 - 1
				# 样本数*隐含神经元个数
				H0 = self.sig(p0, self.Iw, self.bias, self.init_trainset_size)
				self.M = (H0.T * H0).I
				self.beta = self.M * H0.T * T0

				break

		return self

	def fit_train(self, dataPath):
		for t, row in enumerate(DictReader(open(dataPath))):
			del row['Id']
			# 处理label
			y = int(float(row['Label']))
			del row['Label']
			Tn = zeros((1, 7))
			# 处理样本标签
			b = y
			Tn[0][b - 1] = 1
			Tn = Tn * 2 - 1
			# 处理特征
			data = []
			for key in row:
				value = float(row[key])
				data.append(value)
			pn = mat(data)
			H = self.sig(pn, self.Iw, self.bias, 1)
			self.M = self.M - self.M * H.T * (eye(1,1) + H * self.M * H.T).I * H * self.M
			self.beta = self.beta + self.M * H.T * (Tn - H * self.beta)

		self.error_calc(dataPath)

		return self

	def predict(self, dataPath):
		ret = []
		for t, row in enumerate(DictReader(open(dataPath))):
			del row['Id']
			# 处理是否被点击
			y = int(float(row['Label']))
			del row['Label']
			# 处理特征
			data = []
			for key in row:
				value = float(row[key])
				data.append(value)
			p = mat(data)
			HTrain = self.sig(p, self.Iw, self.bias, 1)
			Y = HTrain * self.beta
			# 判断
			ret.append(argmax(Y) + 1)

		return ret

	def error_calc(self, dataPath):
		# 计算训练误差
		correct = 0
		sum = 0
		for t, row in enumerate(DictReader(open(dataPath))):
			del row['Id']
			# 处理是否被点击
			y = int(float(row['Label']))
			del row['Label']
			# 处理特征
			data = []
			for key in row:
				value = float(row[key])
				data.append(value)
			p = mat(data)
			HTrain = self.sig(p, self.Iw, self.bias, 1)
			Y = HTrain * self.beta
			# 判断
			if argmax(Y) + 1 == y:
				correct += 1
			sum += 1
		print("训练准确性为：%f" % (correct / sum))

if __name__ == '__main__':
	elm = OS_ELM(hidden_neuron=180, input_neuron=19, init_size=280)
	network = elm.fit_init("./segment_train.csv")
	# print(network.M)
	network.fit_train("./segment_test.csv")
