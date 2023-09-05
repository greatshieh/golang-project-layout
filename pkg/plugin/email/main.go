package email

import (
	"golang_project_layout/pkg/options"

	"github.com/gin-gonic/gin"
)

type emailPlugin struct{}

var EmailConf = new(options.Email)

func CreateEmailPlug(To, From, Host, Secret, Nickname string, Port int, IsSSL bool) *emailPlugin {
	EmailConf.To = To
	EmailConf.From = From
	EmailConf.Host = Host
	EmailConf.Secret = Secret
	EmailConf.Nickname = Nickname
	EmailConf.Port = Port
	EmailConf.IsSSL = IsSSL
	return &emailPlugin{}
}

func (*emailPlugin) Register(group *gin.RouterGroup) {
	router := new(EmailRouter)
	router.InitRouter(group)
}

func (*emailPlugin) RouterPath() string {
	return "email"
}
