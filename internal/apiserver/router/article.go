package router

import (
	v1 "golang_project_layout/internal/apiserver/controller/v1"

	"github.com/gin-gonic/gin"
)

type ArticleRouter struct{}

func (a *ArticleRouter) InitRouter(Router *gin.RouterGroup) {
	articleRouter := Router.Group("article")
	articleController := new(v1.ArticleController)

	articleRouter.GET("", articleController.List)
	articleRouter.GET(":name", articleController.Get)
}
