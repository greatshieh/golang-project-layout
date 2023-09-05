package router

import (
	system "golang_project_layout/pkg/controller/v1"

	"github.com/gin-gonic/gin"
)

type UserRouter struct{}

func (s *UserRouter) InitRouter(Router gin.IRouter, middleware ...gin.HandlerFunc) {
	userRouter := Router.Group("user")

	userRouterWithoutRecord := Router.Group("user")
	userController := system.ControllerGroupApp.UserController

	userRouter.POST("admin_register", userController.Register)               // 管理员注册账号
	userRouter.POST("login", userController.Login)                           // 用户登录
	userRouter.POST("changePassword", userController.ChangePassword)         // 用户修改密码
	userRouter.POST("setUserAuthority", userController.SetUserAuthority)     // 设置用户权限
	userRouter.DELETE("deleteUser", userController.DeleteUser)               // 删除用户
	userRouter.PUT("setUserInfo", userController.SetUserInfo)                // 设置用户信息
	userRouter.PUT("setSelfInfo", userController.SetSelfInfo)                // 设置自身信息
	userRouter.POST("setUserAuthorities", userController.SetUserAuthorities) // 设置用户权限组
	userRouter.POST("resetPassword", userController.ResetPassword)           // 重置用户权限组

	userRouterWithoutRecord.POST("getUserList", userController.GetUserList) // 分页获取用户列表
	userRouterWithoutRecord.GET("getUserInfo", userController.GetUserInfo)  // 获取自身信息

}
