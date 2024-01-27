package apiserver

import (
	"fmt"
	"golang_project_layout/internal/apiserver/router"
	"golang_project_layout/pkg/app"
	"golang_project_layout/pkg/global"
	"time"

	"golang_project_layout/pkg/plugin/email"

	"github.com/fvbock/endless"
	"github.com/gin-gonic/gin"
	"go.uber.org/zap"
)

type server interface {
	ListenAndServe() error
}

type GenericServer struct {
	Name        string
	Description string
	*gin.Engine
}

func NewServer(name string) *GenericServer {
	if global.GVA_CONFIG.System.Env == "public" {
		gin.SetMode(gin.ReleaseMode) //DebugMode ReleaseMode TestMode
	}

	genericServer := &GenericServer{Name: name, Engine: gin.New()}

	if global.GVA_CONFIG.System.UseMultipoint || global.GVA_CONFIG.System.UseRedis {
		// 开启了多点登录限制，并且使用 Redis
		// 初始化redis服务
		app.Redis()
	}

	// TODO
	// 从db加载jwt数据
	// if global.GVA_DB != nil {
	// 	system.LoadAll()
	// }

	// 注册默认系统基础路由
	Router := genericServer.Engine.Group(global.GVA_CONFIG.System.RouterPrefix)
	// Router.Use(middleware.Cors())
	// 注册中间件
	app.InstalltMiddleware(Router, global.GVA_CONFIG.System.Middleware)
	// 注册限流器
	app.InitstallRateLimiter(Router)

	app.InstalltSystemRouter(Router, global.GVA_CONFIG.System.SystemRouters)

	// 创建email插件
	emailPlugin := email.CreateEmailPlug(
		global.GVA_CONFIG.Email.To,
		global.GVA_CONFIG.Email.From,
		global.GVA_CONFIG.Email.Host,
		global.GVA_CONFIG.Email.Secret,
		global.GVA_CONFIG.Email.Nickname,
		global.GVA_CONFIG.Email.Port,
		global.GVA_CONFIG.Email.IsSSL,
	)
	// 注册需要的插件
	app.InstallPlugin(genericServer.Engine, emailPlugin)

	// 注册应用路由
	router.AppRouter(genericServer.Engine)

	return genericServer
}

func (s *GenericServer) Run() server {
	address := fmt.Sprintf(":%d", global.GVA_CONFIG.System.Addr)
	srv := endless.NewServer(address, s.Engine)
	srv.ReadHeaderTimeout = 20 * time.Second
	srv.WriteTimeout = 20 * time.Second
	srv.MaxHeaderBytes = 1 << 20

	time.Sleep(10 * time.Microsecond)
	global.GVA_LOG.Info("server run success on ", zap.String("address", address))

	global.GVA_LOG.Error(srv.ListenAndServe().Error())
	return srv
}

// func initServer(address string, router *gin.Engine) server {
// 	s := endless.NewServer(address, router)
// 	s.ReadHeaderTimeout = 20 * time.Second
// 	s.WriteTimeout = 20 * time.Second
// 	s.MaxHeaderBytes = 1 << 20
// 	return s
// }
