#coding=utf-8
#__author__='xdzang'
import numpy as np
import matplotlib.pyplot as plt
from sklearn.cluster import SpectralClustering
from sklearn import preprocessing
from sklearn.neighbors import kneighbors_graph
from sklearn import metrics
from sklearn.metrics import pairwise_distances
from sklearn.cluster import AgglomerativeClustering
import Levenshtein

import math

def readdoaminFile(rfilebuf,wfilebuf):
    count = 0
    fwrite = open(wfilebuf, "w")
    fread = open(rfilebuf, "r")
    for line in fread:
        count = count + 1
        fwrite.write(line)
        if count >10000:
            break

    fread.close()
    fwrite.close()

# 从rfilebuf中读取记录
# 聚合相同域名的不同ip，将ttl和firsttime取最小值
# 写入到新文件wfilebuf中
def clusterDomains(rfilebuf, wfilebuf):
    ret = [[""]]    # 最终写入结果

    with open(rfilebuf, "r") as f:
        res = f.readlines()
        lastptr = 0     # 上一条记录的指针

        # 按行读取
        for i in range(0, len(res)):
            arr = res[i].split(",")
            temp = [arr[0], [int(arr[1])], int(arr[2]), int(arr[3])]     # 写入数据结构
            last = ret[lastptr]     # 上一条记录

            # 若当前记录的域名与上一条相同，则聚合
            if temp[0] == last[0]:
                last[1].append(temp[1][0])
                last[2] = temp[2] if (temp[2] < last[2]) else last[2]
                last[3] = temp[3] if (temp[3] < last[3]) else last[3]
            else:
                ret.append(temp)
                lastptr += 1

    ret = ret[1:]

    with open(wfilebuf, "w") as f:
        for item in ret:
            f.write(str(item)[1:-1] + "\n")


def getResolvedIPMatrixOfRawData(rfilebuf,timeWindow):
    matrix = []
    list = []
    templist = []
    flabel = 0
    rlabel = 0
    rslabel = 0
    ftime = 0
    fread = open(rfilebuf, "r")
    for line in fread:
        flabel = line.find(",")
        rlabel = line.rfind(",")
        foundTime = line[rlabel +1 : len(line)]
        subline = line[flabel+1:rlabel]
        rslabel = subline.rfind(",")
        templist = subline[0 :rslabel].split(',')
        if len(matrix) == 0:
            ftime = int(foundTime)
            matrix.append(templist)
        elif int(foundTime) - ftime < timeWindow:
            matrix.append(templist)
        else:
            # cluster classifcation
            break;
        templist = []
        subline =[]
    return matrix
def fast_FluxBotnetDetection(rfilebuf,timeWindow):
    matrix = []
    list = []
    templist = []
    flabel = 0
    rlabel = 0
    ftime = 0
    fread = open(rfilebuf, "r")
    for line in fread:
        flabel = line.find(",")
        rlabel = line.rfind(",")
        foundTime = line[rlabel + 1: len(line)]
        domainName = line[0 :flabel]
        list.append(domainName)
        if len(matrix) == 0:
            ftime = int(foundTime)
            matrix.append(list)
        elif int(foundTime) - ftime < timeWindow:
            matrix.append(list)
        else:
            # cluster domain names in matrix
            myArray = domainNameEditDistanceStandardMatrix(matrix)
            clusterUsingAgglomerativeClustering(myArray)
            #Feature extraction
            #fast_flux identification  classifcation
            # timeWindow is longer than defined
            matrix = []
            matrix.append(list)
            ftime = int(foundTime)
            break;
        templist = []
def domainNameEditDistanceStandardMatrix(list):
    matrix = np.array(list)
    simMatrix = []
    tmplist = []
    for i in range(len(matrix)):
        for j in range(len(matrix)):
            similar = Levenshtein.distance(matrix[i][0],matrix[j][0])
            tmplist.append(similar)
        simMatrix.append(tmplist)
        tmplist = []
    X_train = np.array(simMatrix)
    min_max_scaler = preprocessing.MinMaxScaler()
    X_train_minmax = min_max_scaler.fit_transform(X_train)
    return X_train_minmax

def clusterUsingAgglomerativeClustering(simMatrix):
    knn_graph = kneighbors_graph(simMatrix, 30, include_self=False)
    for connectivity in (None, knn_graph):
        for n_clusters in (5,6,7,8):
            for index, linkage in enumerate(('average', 'complete', 'ward')):
                model = AgglomerativeClustering(linkage=linkage,connectivity=connectivity,n_clusters=n_clusters)
                labels = model.fit_predict(simMatrix)
                Score = metrics.calinski_harabaz_score(simMatrix, labels)
                print "n_clusters=", n_clusters, "linkage=", linkage,"Score =",Score

def calcuSimMatrix(rfilebuf,timeWindow):
    tmplist = []
    matrix = []
    simMatrix = []
    similar = 0.0
    matrix = getResolvedIPMatrixOfRawData(rfilebuf,timeWindow)
    for i in range(len(matrix)):
        for j in range(len(matrix)):
            similar = simFun(matrix[i],matrix[j])
            tmplist.append(similar)
        simMatrix.append(tmplist)
        tmplist =[]
    return simMatrix

def simFun(list1,list2):
    same = 0.0
    diff = 0.0
    sim = 0.0
    if len(list1)==len(list2):
        tmax = len(list1)
        tmin = len(list1)
        for elem in list1:
            if list2.count(elem) == 1:
                same = same +1
            else:
                diff = diff + 1
        if same ==len(list1):
            similarity = 1.0
            return similarity
    elif len(list1)< len(list2):
        tmax = len(list2)
        tmin = len(list1)
        for elem in list1:
            if list2.count(elem) == 1:
                same = same +1
            else:
                diff = diff + 1
    else:
        tmax = len(list1)
        tmin = len(list2)
        for elem in list2:
            if list1.count(elem) == 1:
                same = same +1
            else:
                diff = diff + 1

    sim = same/(tmax+diff)*(1/(1+ math.exp(3 - tmin) ))
    similarity = round(sim,3)
    return similarity


if __name__ == '__main__':
    clusterDomains("domainData_test.dat", "test_out")
    # srcFile = "I:/DNS_xdzang2017_12_07/domainIPMapping_test.dat"
    # destFile = "I:/DNS_xdzang2017_12_07/domainData_test.dat"
    #getResolvedIPMatrixOfRawData(srcFile,3600)
    # list1 =['2130706432', '2130772096', '2132869248', '2134900740', '2139095168', '2139160608', '2139161608', '2139162632', '2141257856']
    # list2= ['2130706432', '2130772096', '2132869248', '2134900740', '2139095168', '2139160608', '2139161608', '2139162632', '2141257855']
    #simFun(list1,list2)
    #calcuSimMatrix(srcFile,3600)

    #readdoaminFile("I:/DNS_xdzang2017_12_07/domainDataSort.dat","I:/DNS_xdzang2017_12_07/domainData_Test.dat")
    # matrix =[["mcafee"],["jiashule"],["ourwebpic"]]
    #domainNameEditDistanceStandardMatrix(matrix)