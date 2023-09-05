package system

import v1 "golang_project_layout/pkg/service/v1"

type ControllerGroup struct {
	CasbinController
	JwtController
	UserController
}

var ControllerGroupApp = new(ControllerGroup)

var userService = v1.SysServiceGroupApp.UserService
var jwtService = v1.SysServiceGroupApp.JwtService
var casbinService = v1.SysServiceGroupApp.CasbinService
