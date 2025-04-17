package gincup

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

func LimitMiddleware(limit int) gin.HandlerFunc {
	return func(c *gin.Context) {
		ch := make(chan struct{}, limit)

		select {
		case ch <- struct{}{}:
			c.Next()
			<-ch
		default:
			c.AbortWithStatus(http.StatusTooManyRequests)
		}
	}
}
