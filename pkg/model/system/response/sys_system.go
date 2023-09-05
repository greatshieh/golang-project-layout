package response

import "golang_project_layout/pkg/options"

type SysConfigResponse struct {
	Config options.Server `json:"config"`
}
