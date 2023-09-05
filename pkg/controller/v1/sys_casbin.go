package system

import (
	"fmt"
	"golang_project_layout/pkg/errcode"
	"golang_project_layout/pkg/model/common/response"
	"golang_project_layout/pkg/model/system/request"
	systemRes "golang_project_layout/pkg/model/system/response"
	"golang_project_layout/pkg/utils"

	"github.com/gin-gonic/gin"
	"github.com/marmotedu/errors"
)

type CasbinController struct{}

// UpdateCasbin
// @Tags      Casbin
// @Summary   更新角色api权限
// @Security  ApiKeyAuth
// @accept    application/json
// @Produce   application/json
// @Param     data  body      request.CasbinInReceive        true  "权限id, 权限模型列表"
// @Success   200   {object}  response.Response{msg=string}  "更新角色api权限"
// @Router    /casbin/UpdateCasbin [post]
func (cas *CasbinController) UpdateCasbin(c *gin.Context) {
	var cmr request.CasbinInReceive
	err := c.ShouldBindJSON(&cmr)
	if err != nil {
		response.WriteResponse(c, errors.WithCode(errcode.ErrBind, err.Error()), nil)
		return
	}
	err = utils.Verify(cmr, utils.AuthorityIdVerify)
	if err != nil {
		response.WriteResponse(c, errors.WithCode(errcode.ErrValidation, err.Error()), nil)
		return
	}
	err = casbinService.UpdateCasbin(cmr.AuthorityId, cmr.CasbinInfos)
	if err != nil {
		response.WriteResponse(c, errors.WithCode(errcode.ErrCasbinUpdate, fmt.Sprintf("%d 权限更新失败", cmr.AuthorityId)), nil)

		return
	}
	response.WriteResponse(c, nil, "更新成功")
}

// GetPolicyPathByAuthorityId
// @Tags      Casbin
// @Summary   获取权限列表
// @Security  ApiKeyAuth
// @accept    application/json
// @Produce   application/json
// @Param     data  body      request.CasbinInReceive                                          true  "权限id, 权限模型列表"
// @Success   200   {object}  response.Response{data=systemRes.PolicyPathResponse,msg=string}  "获取权限列表,返回包括casbin详情列表"
// @Router    /casbin/getPolicyPathByAuthorityId [post]
func (cas *CasbinController) GetPolicyPathByAuthorityId(c *gin.Context) {
	var casbin request.CasbinInReceive
	err := c.ShouldBindJSON(&casbin)
	if err != nil {
		response.WriteResponse(c, errors.WithCode(errcode.ErrBind, err.Error()), nil)
		return
	}
	err = utils.Verify(casbin, utils.AuthorityIdVerify)
	if err != nil {
		response.WriteResponse(c, errors.WithCode(errcode.ErrValidation, err.Error()), nil)
		return
	}
	paths := casbinService.GetPolicyPathByAuthorityId(casbin.AuthorityId)
	response.WriteResponse(c, nil, systemRes.PolicyPathResponse{Paths: paths}, "获取成功")
}
