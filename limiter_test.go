package gincup

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func init() {
	gin.SetMode(gin.ReleaseMode)
}

func TestLimitMiddleware(t *testing.T) {
	// Setup test router
	router := gin.New()
	router.Use(LimitMiddleware(2)) // Limit to 2 concurrent requests
	router.GET("/test", func(c *gin.Context) {
		time.Sleep(100 * time.Millisecond) // Simulate some work
		c.JSON(http.StatusOK, gin.H{"status": "ok"})
	})

	t.Run("single request", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusOK, w.Code)
		assert.JSONEq(t, `{"status":"ok"}`, w.Body.String())
	})

	t.Run("concurrent requests within limit", func(t *testing.T) {
		var wg sync.WaitGroup
		successCount := 0
		mu := sync.Mutex{}

		// Make 2 concurrent requests
		for i := 0; i < 2; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				req := httptest.NewRequest("GET", "/test", nil)
				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)

				mu.Lock()
				if w.Code == http.StatusOK {
					successCount++
				}
				mu.Unlock()
			}()
		}

		wg.Wait()
		assert.Equal(t, 2, successCount, "both requests should succeed")
	})

	t.Run("concurrent requests exceeding limit", func(t *testing.T) {
		var wg sync.WaitGroup
		successCount := 0
		rateLimitedCount := 0
		mu := sync.Mutex{}

		// Make 3 concurrent requests (exceeding limit of 2)
		for i := 0; i < 3; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				req := httptest.NewRequest("GET", "/test", nil)
				w := httptest.NewRecorder()
				router.ServeHTTP(w, req)

				mu.Lock()
				if w.Code == http.StatusOK {
					successCount++
				} else if w.Code == http.StatusTooManyRequests {
					rateLimitedCount++
				}
				mu.Unlock()
			}()
		}

		wg.Wait()
		assert.Equal(t, 2, successCount, "only 2 requests should succeed")
		assert.Equal(t, 1, rateLimitedCount, "1 request should be rate limited")
	})

	t.Run("sequential requests", func(t *testing.T) {
		successCount := 0

		// Make 3 sequential requests
		for i := 0; i < 3; i++ {
			req := httptest.NewRequest("GET", "/test", nil)
			w := httptest.NewRecorder()
			router.ServeHTTP(w, req)

			if w.Code == http.StatusOK {
				successCount++
			}
		}

		assert.Equal(t, 3, successCount, "all sequential requests should succeed")
	})
}
