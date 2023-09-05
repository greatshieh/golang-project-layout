package options

type Server struct {
	JWT         JWT           `mapstructure:"jwt" json:"jwt" yaml:"jwt"`
	Zap         Zap           `mapstructure:"zap" json:"zap" yaml:"zap"`
	Redis       Redis         `mapstructure:"redis" json:"redis" yaml:"redis"`
	Email       Email         `mapstructure:"email" json:"email" yaml:"email"`
	System      System        `mapstructure:"system" json:"system" yaml:"system"`
	RateLimiter []RateLimiter `mapstructure:"ratelimiter" json:"ratelimiter" yaml:"ratelimiter"`

	// gorm
	Mysql  Mysql           `mapstructure:"mysql" json:"mysql" yaml:"mysql"`
	Pgsql  Pgsql           `mapstructure:"pgsql" json:"pgsql" yaml:"pgsql"`
	DBList []SpecializedDB `mapstructure:"db-list" json:"db-list" yaml:"db-list"`

	// 跨域配置
	Cors CORS `mapstructure:"cors" json:"cors" yaml:"cors"`
}
