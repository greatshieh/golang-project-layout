package email

import (
	"golang_project_layout/pkg/global"
	"golang_project_layout/pkg/model/common/response"

	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type EmailController struct{}

var emailService = new(EmailService)

// EmailTest
// @Tags      System
// @Summary   发送测试邮件
// @Security  ApiKeyAuth
// @Produce   application/json
// @Success   200  {string}  string  "{"success":true,"data":{},"msg":"发送成功"}"
// @Router    /email/emailTest [post]
func (s *EmailController) EmailTest(c *gin.Context) {
	err := emailService.EmailTest()
	if err != nil {
		global.GVA_LOG.Error("发送失败!", zap.Error(err))
		response.WriteResponse(c, err, nil, "发送失败")
		return
	}
	response.WriteResponse(c, nil, nil, "发送成功")
}

// SendEmail
// @Tags      System
// @Summary   发送邮件
// @Security  ApiKeyAuth
// @Produce   application/json
// @Param     data  body      EmailResponse  true  "发送邮件必须的参数"
// @Success   200   {string}  string                "{"success":true,"data":{},"msg":"发送成功"}"
// @Router    /email/sendEmail [post]
func (s *EmailController) SendEmail(c *gin.Context) {
	var email EmailResponse
	err := c.ShouldBindJSON(&email)
	if err != nil {
		response.WriteResponse(c, err, nil)

		return
	}
	err = emailService.SendEmail(email.To, email.Subject, email.Body)
	if err != nil {
		global.GVA_LOG.Error("发送失败!", zap.Error(err))
		response.WriteResponse(c, err, nil, "发送失败")
		return
	}
	response.WriteResponse(c, nil, nil, "发送成功")
}
