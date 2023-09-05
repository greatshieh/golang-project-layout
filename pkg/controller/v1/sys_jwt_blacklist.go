package system

import (
	"golang_project_layout/pkg/model/common/response"
	"golang_project_layout/pkg/model/system"

	"github.com/gin-gonic/gin"
)

type JwtController struct{}

// JsonInBlacklist
// @Tags      Jwt
// @Summary   jwt加入黑名单
// @Security  ApiKeyAuth
// @accept    application/json
// @Produce   application/json
// @Success   200  {object}  response.Response{msg=string}  "jwt加入黑名单"
// @Router    /jwt/jsonInBlacklist [post]
func (j *JwtController) JsonInBlacklist(c *gin.Context) {
	token := c.Request.Header.Get("x-token")
	jwt := system.JwtBlacklist{Jwt: token}
	err := jwtService.JsonInBlacklist(jwt)
	if err != nil {
		// global.GVA_LOG.Error("jwt作废失败!", zap.Error(err))
		// response.FailWithMessage("jwt作废失败", c)
		response.WriteResponse(c, err, nil, "jwt作废失败")
		return
	}
	// response.OkWithMessage("jwt作废成功", c)
	response.WriteResponse(c, nil, "jwt作废成功")
}
