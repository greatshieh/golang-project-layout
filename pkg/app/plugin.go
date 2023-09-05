package app

import (
	"golang_project_layout/pkg/utils/plugin"

	"github.com/gin-gonic/gin"
)

func PluginInit(group *gin.RouterGroup, Plugin ...plugin.Plugin) {
	for i := range Plugin {
		PluginGroup := group.Group(Plugin[i].RouterPath())
		Plugin[i].Register(PluginGroup)
	}
}

func InstallPlugin(Router *gin.Engine, Plugin ...plugin.Plugin) {
	PrivateGroup := Router.Group("")
	// fmt.Println("鉴权插件安装==》", PrivateGroup)
	// PrivateGroup.Use(middleware.JWTAuth()).Use(middleware.CasbinHandler())
	PluginInit(PrivateGroup, Plugin...)
}
