package gincup

import (
	"net/http"

	"github.com/gin-gonic/gin"
)

// LimitMiddleware is a middleware that limits the number of requests at the same time.
//
// If the number of requests exceeds the limit, the middleware will return a 429 Too Many Requests status.
func LimitMiddleware(limit uint64) gin.HandlerFunc {
	ch := make(chan struct{}, limit)
	return func(c *gin.Context) {
		select {
		case ch <- struct{}{}:
			defer func() { <-ch }()
			c.Next()
		default:
			c.AbortWithStatus(http.StatusTooManyRequests)
		}
	}
}
