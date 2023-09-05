package middleware

import (
	"errors"
	"golang_project_layout/pkg/global"
	"golang_project_layout/pkg/model/common/response"
	v1 "golang_project_layout/pkg/service/v1"

	"golang_project_layout/pkg/utils"
	"strconv"
	"strings"

	"github.com/gin-gonic/gin"
)

var casbinService = v1.SysServiceGroupApp.CasbinService

// CasbinHandler 拦截器
func CasbinHandler() gin.HandlerFunc {
	return func(c *gin.Context) {
		if global.GVA_CONFIG.System.Env != "develop" {
			waitUse, _ := utils.GetClaims(c)
			//获取请求的PATH
			path := c.Request.URL.Path
			obj := strings.TrimPrefix(path, global.GVA_CONFIG.System.RouterPrefix)
			// 获取请求方法
			act := c.Request.Method
			// 获取用户的角色
			sub := strconv.Itoa(int(waitUse.AuthorityId))
			e := casbinService.Casbin() // 判断策略中是否存在
			success, _ := e.Enforce(sub, obj, act)
			if !success {
				response.WriteResponse(c, errors.New("权限不足"), nil)
				c.Abort()
				return
			}
		}
		c.Next()
	}
}
