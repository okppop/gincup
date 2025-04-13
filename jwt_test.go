package gincup

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/stretchr/testify/assert"
)

func TestJWT(t *testing.T) {
	t.Run("normal web token", func(t *testing.T) {
		j := NewJWT("secret", 1*time.Hour)

		token, err := j.GenerateTokenAndSetSubject("123")
		if err != nil {
			t.Fatal(err)
		}

		sub, err := j.ValidateTokenAndGetSubject(token)
		if err != nil {
			t.Fatal(err)
		}

		if sub != "123" {
			t.Fatal("sub is not 123")
		}
	})

	t.Run("expired token", func(t *testing.T) {
		j := NewJWT("secret123", 1*time.Second)

		token, err := j.GenerateTokenAndSetSubject("123")
		if err != nil {
			t.Fatal(err)
		}

		time.Sleep(2 * time.Second)

		_, err = j.ValidateTokenAndGetSubject(token)
		if err != ErrJWTTokenExpired {
			t.Fatal("err is not ErrJWTTokenExpired")
		}
	})

	t.Run("invalid token", func(t *testing.T) {
		j := NewJWT("secret123", 1*time.Hour)

		_, err := j.ValidateTokenAndGetSubject("sdasdasdasdasd13414")
		if err != ErrJWTInvalidToken {
			t.Fatal("err is not ErrJWTInvalidToken")
		}
	})
}

func TestJWTMiddleware(t *testing.T) {
	j := NewJWT("secret", 1*time.Hour)

	// Setup test router
	router := gin.New()
	router.Use(j.Middleware())
	router.GET("/test", func(c *gin.Context) {
		subject, _ := c.Get("subject")
		c.JSON(http.StatusOK, gin.H{"subject": subject})
	})

	t.Run("valid token", func(t *testing.T) {
		// Generate a valid token
		token, err := j.GenerateTokenAndSetSubject("test123")
		assert.NoError(t, err)

		// Create request with valid token
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+token)

		// Record response
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		// Check response
		assert.Equal(t, http.StatusOK, w.Code)
		assert.JSONEq(t, `{"subject":"test123"}`, w.Body.String())
	})

	t.Run("missing authorization header", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.JSONEq(t, `{"message":"missing Authorization header"}`, w.Body.String())
	})

	t.Run("invalid authorization format", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "InvalidFormat")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.JSONEq(t, `{"message":"invalid Authorization header format"}`, w.Body.String())
	})

	t.Run("expired token", func(t *testing.T) {
		// Create a JWT with very short expiration
		shortJWT := NewJWT("secret", 1*time.Millisecond)
		token, err := shortJWT.GenerateTokenAndSetSubject("test123")
		assert.NoError(t, err)

		// Wait for token to expire
		time.Sleep(2 * time.Millisecond)

		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.JSONEq(t, `{"message":"token expired"}`, w.Body.String())
	})

	t.Run("invalid token", func(t *testing.T) {
		req := httptest.NewRequest("GET", "/test", nil)
		req.Header.Set("Authorization", "Bearer invalid.token.here")
		w := httptest.NewRecorder()
		router.ServeHTTP(w, req)

		assert.Equal(t, http.StatusUnauthorized, w.Code)
		assert.JSONEq(t, `{"message":"invalid token"}`, w.Body.String())
	})
}
