package email

import (
	"github.com/gin-gonic/gin"
)

type EmailRouter struct{}

func (s *EmailRouter) InitRouter(Router *gin.RouterGroup) {
	emailController := new(EmailController)
	{
		Router.POST("emailTest", emailController.EmailTest) // 发送测试邮件
		Router.POST("sendEmail", emailController.SendEmail) // 发送邮件
	}
}
