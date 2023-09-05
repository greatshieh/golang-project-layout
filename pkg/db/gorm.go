package db

import (
	"fmt"
	"golang_project_layout/pkg/global"
	"log"
	"os"
	"time"

	"go.uber.org/zap"
	"gorm.io/gorm/schema"

	"gorm.io/gorm"
	"gorm.io/gorm/logger"
)

type DBBASE interface {
	GetLogMode() string
}

type DataBaseTable interface {
	TableName() string
}

type _gorm struct{}

var Gorm = new(_gorm)

// Config gorm 自定义配置
// Author [SliverHorn](https://github.com/SliverHorn)
func (g *_gorm) Config(prefix string, singular bool) *gorm.Config {
	config := &gorm.Config{
		NamingStrategy: schema.NamingStrategy{
			TablePrefix:   prefix,
			SingularTable: singular,
		},
		DisableForeignKeyConstraintWhenMigrating: true,
	}
	_default := logger.New(newWriter(log.New(os.Stdout, "\r\n", log.LstdFlags)), logger.Config{
		SlowThreshold: 200 * time.Millisecond,
		LogLevel:      logger.Warn,
		Colorful:      true,
	})
	var logMode DBBASE
	switch global.GVA_CONFIG.System.DbType {
	case "mysql":
		logMode = &global.GVA_CONFIG.Mysql
	case "pgsql":
		logMode = &global.GVA_CONFIG.Pgsql
	default:
		logMode = &global.GVA_CONFIG.Mysql
	}

	switch logMode.GetLogMode() {
	case "silent", "Silent":
		config.Logger = _default.LogMode(logger.Silent)
	case "error", "Error":
		config.Logger = _default.LogMode(logger.Error)
	case "warn", "Warn":
		config.Logger = _default.LogMode(logger.Warn)
	case "info", "Info":
		config.Logger = _default.LogMode(logger.Info)
	default:
		config.Logger = _default.LogMode(logger.Info)
	}
	return config
}

// Gorm 初始化数据库并产生数据库全局变量
// Author SliverHorn
func NewGorm() *gorm.DB {
	switch global.GVA_CONFIG.System.DbType {
	case "mysql":
		return gormMysql()
	case "pgsql":
		return gormPgSql()
	default:
		return gormMysql()
	}
}

// RegisterTables 注册数据库表专用
// Author SliverHorn
func RegisterTables(tables ...interface{}) {
	db := global.GVA_DB

	if err := db.AutoMigrate(tables...); err != nil {
		global.GVA_LOG.Error("register table failed", zap.Error(err))
		os.Exit(0)
	}

	global.GVA_LOG.Info("register table success")
}

type writer struct {
	logger.Writer
}

// newWriter writer 构造函数
// Author [SliverHorn](https://github.com/SliverHorn)
func newWriter(w logger.Writer) *writer {
	return &writer{Writer: w}
}

// Printf 格式化打印日志
// Author [SliverHorn](https://github.com/SliverHorn)
func (w *writer) Printf(message string, data ...interface{}) {
	var logZap bool
	switch global.GVA_CONFIG.System.DbType {
	case "mysql":
		logZap = global.GVA_CONFIG.Mysql.LogZap
	case "pgsql":
		logZap = global.GVA_CONFIG.Pgsql.LogZap
	}
	if logZap {
		global.GVA_LOG.Info(fmt.Sprintf(message+"\n", data...))
	} else {
		w.Writer.Printf(message, data...)
	}
}
