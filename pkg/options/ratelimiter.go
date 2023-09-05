package options

type RateLimiter struct {
	Type  string `mapstructure:"type" json:"type" yaml:"type"`
	Rules []Rule `mapstructure:"rules" json:"rules" yaml:"rules"`
}

type Rule struct {
	Key          string `mapstructure:"key" json:"key" yaml:"key"`                // 自定义键值对名称
	FillInterval int64  `mapstructure:"interval" json:"interval" yaml:"interval"` // 间隔多久时间放N个令牌
	Capacity     int64  `mapstructure:"capacity" json:"capacity" yaml:"capacity"` // 令牌桶容量
	Quantum      int64  `mapstructure:"quantum" json:"quantum" yaml:"quantum"`    // 每次到达时间间隔后所放的具体令牌数量
}
