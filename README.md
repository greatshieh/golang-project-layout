# Golang应用项目框架

参照[gin-vue-admin](https://github.com/flipped-aurora/gin-vue-admin)和[极客时间Go语言项目开发实战](https://time.geekbang.org/column/intro/100079601?tab=catalog)及其[源码](https://github.com/marmotedu/iam)实现

在非web应用的基础上, 实现用户登录, jwt, 权限管理

## 项目结构

```shell
├── cmd
│   └── apiserver
├── configs
├── docs
├── internal
│   └── apiserver
│       ├── controller
│       │   └── v1
│       ├── model
│       ├── router
│       └── service
│           └── v1
└── pkg
    ├── app
    │   └── internal
    ├── controller
    │   └── v1
    ├── db
    ├── errcode
    ├── global
    ├── middleware
    ├── model
    │   ├── common
    │   │   ├── request
    │   │   └── response
    │   └── system
    │       ├── request
    │       └── response
    ├── options
    ├── plugin
    │   └── email
    │       ├── api
    │       ├── config
    │       ├── global
    │       ├── model
    │       │   └── response
    │       ├── router
    │       ├── service
    │       └── utils
    ├── router
    ├── service
    │   └── v1
    └── utils
        └── plugin
```

| 文件夹          | 说明                    | 描述                |
|----------------|------------------------|--------------------|
| `cmd`          | 应用程序入口             | 应用程序主程序        |
| `-apiserver`   | apiserver程序入口       | apiserver应用主程序|
| `configs`      | 配置文件                 | yaml配置文件 |
| `internal`     | 应用程序实现              | 每个文件夹对应一个应用程序 |
| `-apiserver`   | 应用程序apiserver的实现 |                          |
| `--controller` | 应用程序控制器的实现     |                          |
| `--model`      | 应用程序相关模式的实现     |                          |
| `--router`     | 应用程序路由的定义        |                          |
| `--service`    | 应用程序服务程序的实现        |                          |
| `pkg`          | pkg包                   | 可以被应用程序和外部程序调用 |
| `-app`         | 系统级应用               | 系统及初始化函数           |
| `--internal`   | 初始化函数               | 只能被`app`层调用          |
| `-controller`   | 系统应用的控制器          |                          |
| `-db`          | 数据库                   | 数据库连接和配置           |
| `-errcode`     | 定义统一的错误码           |                         |
| `-global`      | 全局对象                 | 全局对象                 |
| `-middleware`  | 中间件定义                 |                       |
| `-model`       | 系统级模型                 |                       |
| `-options`     | 组件配置                 | 组件结构体定义, 与yaml配置对应 |
| `-plugin`      | 系统级插件工具            |                       |
| `-router`      | 系统级路由定义            |                       |
| `-service`     | 系统级服务                |                       |
| `-utils`       | 工具包                   | 工具函数的封装 |
