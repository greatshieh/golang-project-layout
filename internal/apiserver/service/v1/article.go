package v1

import (
	"golang_project_layout/internal/apiserver/model"
)

type ArticleService struct{}

func (articleService *ArticleService) GetArticleList() (list interface{}, total int64, err error) {
	list = []model.Article{{Title: "123"}}
	total = 100
	err = nil

	if err != nil {
		return nil, 0, err
	}
	return list, total, err
}

func (articleService *ArticleService) GetArticleOne() (article *model.Article, err error) {
	article = &model.Article{Title: "this is a article", Desc: "this is description", Author: "Ivan"}
	// err = errors.WithCode(errcode.ErrDatabase, "未找到")
	err = nil

	// if err != nil {
	// 	panic("模拟异常发生")
	// }

	return article, err
}
