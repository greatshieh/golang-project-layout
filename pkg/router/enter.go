package router

import "github.com/gin-gonic/gin"

type Router interface {
	InitRouter(Router gin.IRouter, middleware ...gin.HandlerFunc)
}
