package router

import (
	system "golang_project_layout/pkg/controller/v1"

	"github.com/gin-gonic/gin"
)

type JwtRouter struct{}

func (s *JwtRouter) InitRouter(Router gin.IRouter, middleware ...gin.HandlerFunc) {
	jwtRouter := Router.Group("jwt")
	jwtController := system.ControllerGroupApp.JwtController

	jwtRouter.POST("jsonInBlacklist", jwtController.JsonInBlacklist) // jwt加入黑名单

}
