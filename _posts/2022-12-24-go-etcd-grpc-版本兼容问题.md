---
layout:     post
title:      "Go 导包 etcd 与 grpc 版本兼容问题"
subtitle:   "包管理"
date:       2022-12-24 16:45:00
author:     "WR"
hidden: false
tags:
- 包
- Go
---

#### 背景

​		在一次代码开发过程中当我执行 go mod tidy 时，突然报了以下错误

```go
google.golang.org/grpc/naming: module google.golang.org/grpc@latest found (v1.48.0), but does not contain package google.golang.org/grpc/naming
```

#### 原因

​		ETCD 中使用的旧版本 gRPC 库与最新版本的 gRPC 库不兼容，需要在go.mod中将gRPC替换为 v1.29.1（etcd v3.4.9+要求grpc v1.29.1之前的，从下一个版本开始断代）版本的即可。

#### 解决方案

​		在 go.mod 文件中添加 <u>replace google.golang.org/grpc => google.golang.org/grpc v1.29.1</u>。如果在 go.mod 文件里面发现一个 google.golang.org/grpc/example 包，删除即可，否则执行 go mod tidy 还会报错

注意：grpc的版本要看etcd的版本，比如etcd v3.3.20 的 release 版本要求 grpc 的版本是 v1.26.0 之前的。总之，etcd的断代，不是etcd本身，而是grpc断代了