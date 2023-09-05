package limiter

import (
	"golang_project_layout/pkg/errcode"
	"golang_project_layout/pkg/model/common/response"
	"golang_project_layout/pkg/options"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/juju/ratelimit"
	"github.com/marmotedu/errors"
)

type RouterLimiter struct {
	*Limiter
}

func NewRouterLimiter() LimiterIface {
	return &RouterLimiter{
		Limiter: &Limiter{limiterBuckets: make(map[string]*ratelimit.Bucket)},
	}
}

func (l *RouterLimiter) Key(c *gin.Context) string {
	uri := c.Request.RequestURI
	index := strings.Index(uri, "?")
	if index == -1 {
		return uri
	}

	return uri[:index]
}

func (l *RouterLimiter) GetBucket(key string) (*ratelimit.Bucket, bool) {
	bucket, ok := l.limiterBuckets[key]
	return bucket, ok
}

func (l *RouterLimiter) AddBuckets(rules ...options.Rule) {
	for _, rule := range rules {
		if _, ok := l.limiterBuckets[rule.Key]; !ok {
			l.limiterBuckets[rule.Key] = ratelimit.NewBucketWithQuantum(time.Duration(rule.FillInterval)*time.Second, rule.Capacity, rule.Quantum)
		}
	}
}

func (l *RouterLimiter) Register() gin.HandlerFunc {
	return func(c *gin.Context) {
		key := l.Key(c)
		if bucket, ok := l.GetBucket(key); ok {
			count := bucket.TakeAvailable(1)
			if count == 0 {
				response.WriteResponse(c, errors.WithCode(errcode.ErrTooManyRequests, "限流等待"), nil)
				c.Abort()
				return
			}
		}

		c.Next()
	}
}
