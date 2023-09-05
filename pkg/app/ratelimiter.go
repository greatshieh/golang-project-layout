package app

import (
	"golang_project_layout/pkg/global"
	"golang_project_layout/pkg/middleware"

	"github.com/gin-gonic/gin"
)

func InitstallRateLimiter(router gin.IRouter) {
	for _, rl := range global.GVA_CONFIG.RateLimiter {
		router.Use(middleware.RateLimiter(rl.Type, rl.Rules...))
	}
}
