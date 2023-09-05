package app

import (
	"fmt"
	"golang_project_layout/docs"
	"golang_project_layout/pkg/global"
	"golang_project_layout/pkg/router"
	"net/http"

	"github.com/gin-gonic/gin"
	swaggerFiles "github.com/swaggo/files"
	ginSwagger "github.com/swaggo/gin-swagger"
)

// 初始化系统路由
func InstalltSystemRouter(engine gin.IRouter, routers []string) {
	// 注册swagger路由
	docs.SwaggerInfo.BasePath = global.GVA_CONFIG.System.RouterPrefix
	engine.GET(global.GVA_CONFIG.System.RouterPrefix+"/swagger/*any", ginSwagger.WrapHandler(swaggerFiles.Handler))
	global.GVA_LOG.Info("register swagger handler")

	// 添加统一的路由前缀
	// PublicGroup := engine.Group(global.GVA_CONFIG.System.RouterPrefix)

	// 健康监测
	engine.GET("/health", func(c *gin.Context) {
		c.JSON(http.StatusOK, "ok")
	})

	defaultRouters := defaultRouter()

	for _, r := range routers {
		dr, ok := defaultRouters[r]
		if !ok {
			global.GVA_LOG.Error(fmt.Sprintf("未找到 %s 相关路由", r))
			continue
		}

		dr.InitRouter(engine)
	}
	global.GVA_LOG.Info("system router register success")
}

func defaultRouter() map[string]router.Router {
	return map[string]router.Router{
		"jwt":  &router.JwtRouter{},
		"user": &router.UserRouter{},
	}
}
