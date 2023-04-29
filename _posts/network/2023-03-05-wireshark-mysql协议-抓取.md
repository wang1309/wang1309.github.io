---
layout:     post
title:      "Mysql 协议抓包"
subtitle:   "网络"
date:       2023-03-05 10:48:00
author:     "WR"
hidden: false
tags:
- 网络
---

#### 背景

有时候在本地调试mysql的时候需要抓取mysql协议包，我们可以使用 tcpdump、wireshark 等工具。由于wireshark属于界面友好型，所以通常使用wireshark进行抓包。

#### 流程

在本地部署的mysql，客户端和服务端都位于同一台机器，所以需要抓取本地回环网络接口，如下图所示：

<img width="856" alt="image" src="https://user-images.githubusercontent.com/20272951/222939543-27a09541-0aef-4fda-950a-189ce3dda712.png">


然后使用命令过滤mysql数据包：tcp.dstport == 3306 and mysql.query

<img width="857" alt="image" src="https://user-images.githubusercontent.com/20272951/222939549-62020afe-e2cb-4a4c-9654-630ec01aee42.png">

引用：https://callmejiagu.github.io/2018/10/26/WireShark-%E5%88%86%E6%9E%90MySQL%E7%BD%91%E7%BB%9C%E5%8D%8F%E8%AE%AE%E4%B8%AD%E7%9A%84%E6%95%B0%E6%8D%AE%E5%8C%85%EF%BC%88%E4%BA%8C%EF%BC%89/
