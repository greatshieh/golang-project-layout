package options

type System struct {
	Env           string   `mapstructure:"env" json:"env" yaml:"env"`                                  // 环境值
	Addr          int      `mapstructure:"addr" json:"addr" yaml:"addr"`                               // 端口值
	DbType        string   `mapstructure:"db-type" json:"db-type" yaml:"db-type"`                      // 数据库类型:mysql(默认)|sqlite|sqlserver|postgresql
	UseRedis      bool     `mapstructure:"use-redis" json:"use-redis" yaml:"use-redis"`                // 使用redis
	UseMultipoint bool     `mapstructure:"use-multipoint" json:"use-multipoint" yaml:"use-multipoint"` // 多点登录限制, 禁止用户多点在线
	RouterPrefix  string   `mapstructure:"router-prefix" json:"router-prefix" yaml:"router-prefix"`    // 路由前缀
	SystemRouters []string `mapstructure:"system-router" json:"system-router" yaml:"system-router"`    // 默认系统路由
	Middleware    []string `mapstructure:"middleware" json:"middleware" yaml:"middleware"`             // 系统中间件
	Plugins       []string `mapstructure:"plugins" json:"plugins" yaml:"plugins"`                      // 系统插件
}
