package app

import (
	"golang_project_layout/pkg/global"
	"golang_project_layout/pkg/middleware"

	"github.com/gin-gonic/gin"
)

// 注册中间件
func InstalltMiddleware(router gin.IRouter, mw []string) {
	defaultMiddleware := defaultMiddleware()
	for _, m := range mw {
		if mw, ok := defaultMiddleware[m]; ok {
			router.Use(mw)
		}
	}
	global.GVA_LOG.Info("middleware register success")
}

func defaultMiddleware() map[string]gin.HandlerFunc {
	return map[string]gin.HandlerFunc{
		// 异常捕捉中间件
		"recovery": middleware.Recovery(true),
		// jwt认证中间件
		"jwt": middleware.JWTAuth(),
		// 操作记录
		"access_log": middleware.AccessLog(),
	}
}
