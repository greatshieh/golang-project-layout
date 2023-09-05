package router

import "github.com/gin-gonic/gin"

func AppRouter(r *gin.Engine) {
	articleGroup := r.Group("")
	articleRoute := new(ArticleRouter)
	articleRoute.InitRouter(articleGroup)
}
