# FastFluxDetection
A fast-flux domains' detection and judgement mechanism based on Levenshtein algorithm

## 实现模块

- 流式检测域名活动原始数据记录，根据解析IP聚合记录
- 计算所有域名的二级，三级域标签两两之间的编辑距离（使用python-levenshtein实现）
- 计算已知恶意域名的特征向量
- DBScan聚类编辑距离
- KMeans聚类域名的特征向量
- 计算KMeans聚类簇，DBScan聚类簇的Jaccard Index

## DBScan聚类编辑距离

#### 介绍

以每个域名与其他所有域名二级（三级）标签之间的编辑距离作为数据点之间的距离，使用DBScan算法对域名数据聚类

#### DBScan参数

eps=3，minpts=3

## KMeans聚类已知恶意域名的特征向量

#### 介绍

根据计算得到的已知恶意域名的特征向量，使用KMeans算法对特征向量聚类

特征向量格式为：[二级域名2元组adm, 三级域名2元组adm, 二级域名3元组adm, 三级域名3元组adm, 二级域名熵, 三级域名熵, 二级域名长度, 三级域名长度, 二级域名数字比, 三级域名数字比]

*adm：平均数，标准差，中位数*

#### KMeans参数

k = 10，距离计算方式：9维闵可夫斯基距离

