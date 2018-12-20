# FastFluxDetection
A fast-flux domains' detection and judgement mechanism

Using DBScan and KMeans algorithms to determine the type of generation algorithm

Using OS-ELM to categorize fast-flux and non-fast-flux domains online

Using Logistic model to categorize fast-flux and non-fast-flux domains offline

## 目录结构

```
.
├── data
│   ├── example
│   ├── feature_vector
│   ├── levenshtein_distance
│   └── train_set
├── lib
│   └── source_code
├── modules
│   ├── Cluster-DBScan-KMeans
│   ├── Model
│   ├── Offline-Logistic
│   └── Online-OSELM
├── utils
└── README.md
```

- /data：实验中所有数据。各个目录下的readme.md说明了该目录下文件的作用
  - /raw_data：原始数据
  - /train_set：机器学习训练集
- /lib：C++库文件
  - /source_code：C++库文件源代码
- /modules：功能模块
  - Cluster-DBScan-KMeans：聚类模块
  - Model：原始数据获取模块
  - Offline-Logistic：离线的Logistic模型
  - Online-OSELM：在线的顺序极限学习机模型
- /utils：通用功能

## 功能模块

- 聚类模块

  - Levenshtein_DBScan
    - 流式检测域名活动原始数据记录，根据解析IP聚合记录
    - 计算所有域名的二级，三级域标签两两之间的编辑距离
    - DBScan聚类编辑距离
  - FeatureVector_KMeans
    - 计算已知恶意域名的特征向量
    - KMeans聚类域名的特征向量
  - JaccardIndex
    - 计算KMeans聚类簇，DBScan聚类簇的Jaccard Index

- 原始数据获取模块

  - config：数据库配置

  - mysql：数据库连接基本操作的封装

    **获取数据时，运行在211.65.193.23上**

  - model：获取域名测度信息的model

  - get_vector：求域名特征向量

- 离线的Logistic模型

- 在线的顺序极限学习机模型

## 使用

- 在线/离线分类

  - 获取原始数据的特征向量：python3 modules/Model/get_vector.py

  - 在线分类：python3 modules/Online-OSELM/Online-OSELM.py

  - 离线分类：python3 modules/Offline-Logistic/Offline_Logistic.py


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

## OS-ELM & Logistic

#### 介绍

使用在线顺序极限学习机和Logistic模型，分别在线和离线地对域名特征向量分类

特征向量格式为：[label, TTL平均值, whois是否过期, whois完整度, 解析IP地理分布熵, 通信对端IP与解析IP之间地理距离平均值]

#### OS-ELM参数

输入节点：5个，隐层节点：60个

