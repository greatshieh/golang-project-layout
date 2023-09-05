package system

import "golang_project_layout/pkg/options"

// import (
// 	"golang_project_layout/pkg/config"
// )

// 配置文件结构体
type System struct {
	Config options.Server `json:"config"`
}
