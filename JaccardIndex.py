#!coding=utf8

import io
import numpy as np

def getFeatureVector(rfile):
	fv = []
	with io.open(rfile, "r") as f:
		for line in f.readlines()[:50]:
			fv.append(eval(line))

	return fv

def getLevenshteinDistance(rfile):
	ld = []
	with io.open(rfile, "r") as f:
		for line in f.readlines()[:50]:
			ld.append(eval(line))

	return ld

def jaccardIndex(arr, i, j):
	setA = set()
	setB = set()

	for item in arr:
		if int(item[1]) == i:
			setA.add(item[0])
		if int(item[2]) == j:
			setB.add(item[0])

	if len(setA | setB) != 0:
		return len(setA & setB) / len(setA | setB)
	else:
		return 0

def main(fv, ld, wfile):
	fv_ld = np.hstack((np.array(getFeatureVector(fv)), 
		np.array(getLevenshteinDistance(ld))))
	fv_ld = np.delete(fv_ld, 2, axis=1)

	size_fv = int(max(fv_ld[:,1])) + 1
	size_ld = int(max(fv_ld[:,2])) + 1#+ 1)
	
	ji = [[0.0 for y in range(size_ld)] for x in range(size_fv)]

	for i in range(size_fv):
		for j in range(size_ld):
			ji[i][j] = jaccardIndex(fv_ld, i, j)

	with io.open(wfile, "w") as f:
		for item in ji:
			f.write(str(item) + "\n")


if __name__ == '__main__':
	main("NGram-KMeans/data/feature_test_kmeans", 
		"NGram-KMeans/data/feature_test_kmeans", 
		"ji_res.dat")