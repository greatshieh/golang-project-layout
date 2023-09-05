package v1

import (
	v1 "golang_project_layout/internal/apiserver/service/v1"
	"golang_project_layout/pkg/model/common/response"

	"github.com/gin-gonic/gin"
)

type ArticleController struct{}

var articleService = new(v1.ArticleService)

func (a *ArticleController) List(c *gin.Context) {
	list, total, err := articleService.GetArticleList()

	if err != nil {
		response.WriteResponse(c, err, nil)
	}

	response.WriteResponse(c, nil, response.PageResult{Total: total, List: list, Page: 3, PageSize: 10}, "success")
}

func (a *ArticleController) Get(c *gin.Context) {
	article, err := articleService.GetArticleOne()

	response.WriteResponse(c, err, article, "success")
}
