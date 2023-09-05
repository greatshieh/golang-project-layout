# 限流器中间件

当前实现路由限流器, 客户IP限流器

- [x] 路由限流器
- [x] 客户IP限流器

## 定义

用工厂模式创建限流器, 首先创建限流器接口

```go
type LimiterIface interface {
 // 获取对应的限流器的键值名称
 Key(c *gin.Context) string
 // 获取令牌桶
 GetBucket(key string) (*ratelimit.Bucket, bool)
 // 新增多个令牌桶
 AddBuckets(rules ...LimiterBucketRules)
 // 注册限流器
 Register() gin.HandlerFunc
}
```

定义规则对象。 在路由限流器 `RouterLimiter` 中使用[https://github.com/juju/ratelimit](https://github.com/juju/ratelimit)。

```go
type LimiterBucketRules struct {
 // 自定义键值对名称
 Key string
 // 间隔多久时间放N个令牌
 FillInterval int64
 // 令牌桶容量
 Capacity int64
 // 每次到达时间间隔后所放的具体令牌数量
 Quantum int64
}
```

- `Key` - 需要限流的路由路径, 用于在拦截时根据路径查找对应的规则。
- `FillInterval` - 间隔时间, 以秒为单位。
- `Capacity` - 令牌桶的容量
- `Quantum` - 每次到达时间间隔后所放的具体令牌数量

在客户IP限流器中, 只需要限制每个IP地址在一段时间内的访问次数, 因此不需要再返回令牌, 因此只需要用到 `FillInterval` 和 `Capacity` 变量。

## 使用

```go
// 新建一个限流器
func RateLimiter(limiterType string, rules ...options.Rule) gin.HandlerFunc {
 var l limiter.LimiterIface
 switch limiterType {
 case "router":
  l = limiter.NewRouterLimiter()
 case "ip":
  l = limiter.NewIPLimiter()
 default:
  l = limiter.NewRouterLimiter()
 }

 l.AddBuckets(rules...)
 return l.Register()
}
```

根据输入的限流器类型, 自动创建限流器, 同时设置相应的规则。

```go
RateLimiter("ip", options.Rule{FillInterval: 60, Capacity: 2})
```
