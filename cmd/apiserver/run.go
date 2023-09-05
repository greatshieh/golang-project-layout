package main

import (
	"golang_project_layout/internal/apiserver"
	"golang_project_layout/pkg/app"
	"golang_project_layout/pkg/db"
	"golang_project_layout/pkg/global"

	"go.uber.org/zap"
)

func main() {
	global.GVA_VP = app.Viper() // 初始化Viper
	global.GVA_LOG = app.Zap()  // 初始化zap日志库
	zap.ReplaceGlobals(global.GVA_LOG)
	global.GVA_DB = db.NewGorm() // gorm连接数据库
	// db.DBList()
	if global.GVA_DB != nil {
		// tables := []interface{}{system.SysUser{}, system.JwtBlacklist{}, system.SysUserAuthority{}, system.SysAuthority{}}
		// db.RegisterTables(tables...) // 初始化表
		// 程序结束前关闭数据库链接
		db, _ := global.GVA_DB.DB()
		defer db.Close()
	}
	apiserver.NewServer("api server").Run()
}
