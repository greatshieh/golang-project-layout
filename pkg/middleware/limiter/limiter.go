package limiter

import (
	"golang_project_layout/pkg/options"

	"github.com/gin-gonic/gin"
	"github.com/juju/ratelimit"
)

// 基于https://github.com/juju/ratelimit实现限流器

type LimiterIface interface {
	// 获取对应的限流器的键值名称
	Key(c *gin.Context) string
	// 获取令牌桶
	GetBucket(key string) (*ratelimit.Bucket, bool)
	// 新增多个令牌桶
	AddBuckets(rules ...options.Rule)
	// 限流器执行
	Register() gin.HandlerFunc
}

type Limiter struct {
	limiterBuckets map[string]*ratelimit.Bucket
}
