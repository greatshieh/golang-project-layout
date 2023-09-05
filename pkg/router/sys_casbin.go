package router

import (
	system "golang_project_layout/pkg/controller/v1"

	"github.com/gin-gonic/gin"
)

type CasbinRouter struct{}

func (s *CasbinRouter) InitRouter(Router *gin.RouterGroup, middleware ...gin.HandlerFunc) {
	casbinRouter := Router.Group("casbin")
	casbinRouterWithoutRecord := Router.Group("casbin")
	casbinController := system.ControllerGroupApp.CasbinController
	{
		casbinRouter.POST("updateCasbin", casbinController.UpdateCasbin)
		casbinRouterWithoutRecord.POST("getPolicyPathByAuthorityId", casbinController.GetPolicyPathByAuthorityId)
	}
}
