#!coding=utf8

import numpy as np
import matplotlib.pyplot as plt
from mpl_toolkits.mplot3d import Axes3D

# 作出三维散点图，并根据分类结果标出不同颜色
# 参数格式：
# 		data：numpy.array，坐标(x,y,z)的数组
#		labels：一维数组，表示聚类算法的分类结果
def plot_3d_scatter(data, labels=[]):
	# 设置labels参数默认值为全0
	labels = labels if len(labels) != 0 else [0 for x in range(len(data))]

	fig = plt.figure()
	ax = fig.gca(projection='3d')
	ax.scatter(data[:,0],data[:,1], data[:,2], c=labels)
	plt.show()

# 作出二维散点图，并根据分类结果标出不同颜色
# 参数格式：
# 		data：numpy.array，坐标(x,y)的数组
#		labels：一维数组，表示聚类算法的分类结果
def plot_scatter(data, labels=[]):
	# 设置labels参数默认值为全0
	labels = labels if len(labels) != 0 else [0 for x in range(len(data))]

	fig = plt.figure()
	ax = fig.gca()
	ax.scatter(data[:,0],data[:,1], c=labels)
	plt.show()