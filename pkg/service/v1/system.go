package v1

type SysServiceGroup struct {
	CasbinService
	JwtService
	UserService
}

var SysServiceGroupApp = new(SysServiceGroup)
