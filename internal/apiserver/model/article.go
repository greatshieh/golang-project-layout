package model

import (
	"golang_project_layout/pkg/global"
)

type Article struct {
	global.GVA_MODEL
	Title  string `json:"title"`
	Desc   string `json:"desc"`
	Author string `json:"author"`
}
