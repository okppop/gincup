package gincup

import (
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
)

var (
	ErrJWTInvalidToken = errors.New("invalid token")
	ErrJWTTokenExpired = errors.New("token expired")
)

type JWT struct {
	Secret         []byte
	ExpireDuration time.Duration
}

func NewJWT(secret string, expireDuration time.Duration) *JWT {
	if secret == "" {
		panic("secret is required")
	}

	if expireDuration <= 0 {
		panic("expire duration must be greater than 0")
	}

	return &JWT{
		Secret:         []byte(secret),
		ExpireDuration: expireDuration,
	}
}

func (j *JWT) GenerateToken(sub string) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": sub,
		"exp": jwt.NewNumericDate(time.Now().Add(j.ExpireDuration)),
	}).SignedString(j.Secret)
}

func (j *JWT) ValidateTokenAndGetSubject(token string) (string, error) {
	t, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		return j.Secret, nil
	})
	if err != nil {
		if errors.Is(err, jwt.ErrTokenExpired) {
			return "", ErrJWTTokenExpired
		}
		return "", ErrJWTInvalidToken
	}

	claims, ok := t.Claims.(jwt.MapClaims)
	if !ok {
		return "", ErrJWTInvalidToken
	}

	// get subject
	return claims.GetSubject()
}

func (j *JWT) Middleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		// get token from Authorization header
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "missing Authorization header"})
			c.Abort()
			return
		}

		// trim Bearer prefix
		token := strings.TrimPrefix(authHeader, "Bearer ")
		// no prefix was trimmed
		if token == authHeader {
			c.JSON(http.StatusUnauthorized, gin.H{"message": "invalid Authorization header format"})
			c.Abort()
			return
		}

		// validate token and get subject
		subject, err := j.ValidateTokenAndGetSubject(token)
		if err != nil {
			var message string
			switch {
			case errors.Is(err, ErrJWTTokenExpired):
				message = "token expired"
			case errors.Is(err, ErrJWTInvalidToken):
				message = "invalid token"
			default:
				message = "unauthorized"
			}
			c.JSON(http.StatusUnauthorized, gin.H{"message": message})
			c.Abort()
			return
		}

		// set subject to context
		c.Set("subject", subject)
		c.Next()
	}
}
