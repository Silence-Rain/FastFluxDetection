# FastFluxDetection
A fast-flux domains' detection and judgement mechanism based on Levenshtein algorithm

## 实现模块

- 流式检测域名活动原始数据记录，根据解析IP聚合
- 计算所有域名的二级，三级域标签两两之间的编辑距离（使用python-levenshtein实现）
- DBSCAN聚类编辑距离

## DBSCAN聚类编辑距离

#### 介绍

对每个域名与其他所有域名二级（三级）标签之间的编辑距离，使用DBSCAN算法对编辑距离聚类。

#### DBSCAN参数

eps=0.5，minpts=10

*（由于编辑距离是整数，所以对每一个取值聚类，可以后续再调整为更大尺度）*

#### 测试数据

从100个域名二级域名标签两两之间的编辑距离矩阵中，取上三角部分。共4950个距离对

*（距离对格式：[域名i, 域名j, i与j的编辑距离]）*

#### 测试结果

- 根据编辑距离，算法将4950个距离对分为13类，核心对象4945个
- 将距离对中的域名信息(域名i, 域名j)元组按照算法结果分类，并写入文件中