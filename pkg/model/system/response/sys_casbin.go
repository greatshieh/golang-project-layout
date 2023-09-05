package response

import "golang_project_layout/pkg/model/system/request"

type PolicyPathResponse struct {
	Paths []request.CasbinInfo `json:"paths"`
}
