package limiter

import (
	"context"
	"golang_project_layout/pkg/errcode"
	"golang_project_layout/pkg/global"
	"golang_project_layout/pkg/model/common/response"
	"golang_project_layout/pkg/options"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/juju/ratelimit"
	"github.com/marmotedu/errors"
	"go.uber.org/zap"
)

type IPLimiter struct {
	LimitCountIP    int64
	LimitIntervalIP int64
	LimiterBuckets  map[string]*ratelimit.Bucket
}

func NewIPLimiter() LimiterIface {
	return &IPLimiter{LimiterBuckets: make(map[string]*ratelimit.Bucket)}
}

func (l *IPLimiter) Key(c *gin.Context) string {
	return "GVA_Limit" + c.ClientIP()
}

func (l *IPLimiter) GetBucket(key string) (*ratelimit.Bucket, bool) {
	bucket, ok := l.LimiterBuckets[key]
	return bucket, ok
}

func (l *IPLimiter) AddBuckets(rules ...options.Rule) {
	for _, rule := range rules {
		if rule.FillInterval > 0 {
			l.LimitIntervalIP = rule.FillInterval
		}

		if rule.Capacity > 0 {
			l.LimitCountIP = rule.Capacity
		}
	}
}

func (l *IPLimiter) Register() gin.HandlerFunc {
	return func(c *gin.Context) {
		key := l.Key(c)
		if err := l.CheckOrMark(key); err != nil {
			response.WriteResponse(c, errors.WithCode(errcode.ErrLimitedIP, err.Error()), nil)
			c.Abort()
			return
		}

		c.Next()
	}
}

func (l *IPLimiter) CheckOrMark(key string) (err error) {
	// ! 判断是否开启redis, 需要在config中配置开启redis
	if global.GVA_REDIS == nil {
		// 没有开启redis, 规则保存在内存中
		if bucket, ok := l.GetBucket(key); !ok {
			l.LimiterBuckets[key] = ratelimit.NewBucketWithQuantum(time.Duration(l.LimitIntervalIP)*time.Second, l.LimitCountIP, l.LimitCountIP)
			l.LimiterBuckets[key].TakeAvailable(1)
		} else {
			// 已经添加了规则
			count := bucket.TakeAvailable(1)
			if count == 0 {
				err = errors.New("请求太过频繁，请稍后再试")
			}
		}
	} else {
		// 开启redis, 规则保存在redis中
		if err = setLimitWithTime(key, l.LimitCountIP, time.Duration(l.LimitIntervalIP)*time.Second); err != nil {
			global.GVA_LOG.Error("limit", zap.Error(err))
		}
	}

	return err
}

// setLimitWithTime 设置访问次数
func setLimitWithTime(key string, limit int64, interval time.Duration) error {
	// 检查key是否存在
	count, err := global.GVA_REDIS.Exists(context.Background(), key).Result()
	if err != nil {
		return err
	}
	if count == 0 {
		// key值不存在
		pipe := global.GVA_REDIS.TxPipeline()
		// 设置key值
		pipe.Incr(context.Background(), key)
		// 设置有效期
		pipe.Expire(context.Background(), key, interval)
		_, err = pipe.Exec(context.Background())
		return err
	} else {
		// key存在
		if times, err := global.GVA_REDIS.Get(context.Background(), key).Int(); err != nil {
			return err
		} else {
			if int64(times) >= limit {
				// 访问次数达到允许次数
				if t, err := global.GVA_REDIS.PTTL(context.Background(), key).Result(); err != nil {
					return errors.New("请求太过频繁，请稍后再试")
				} else {
					// 返回以毫秒为单位的剩余过期时间
					return errors.New("请求太过频繁, 请 " + t.String() + " 秒后尝试")
				}
			} else {
				// 在允许次数内, redis + 1
				return global.GVA_REDIS.Incr(context.Background(), key).Err()
			}
		}
	}
}
