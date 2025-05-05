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
	secret         []byte
	expireDuration time.Duration
}

func NewJWT(secret string, expireDuration time.Duration) *JWT {
	if secret == "" {
		panic("secret is required")
	}

	if expireDuration <= 0 {
		panic("expire duration must be greater than 0")
	}

	return &JWT{
		secret:         []byte(secret),
		expireDuration: expireDuration,
	}
}

/*
GenerateTokenAndSetSubject generates a JWT token and sets the subject to the token.

The token will expire after the expire duration.
*/
func (j *JWT) GenerateTokenAndSetSubject(sub interface{}) (string, error) {
	return jwt.NewWithClaims(jwt.SigningMethodHS256, jwt.MapClaims{
		"sub": sub,
		"exp": jwt.NewNumericDate(time.Now().Add(j.expireDuration)),
	}).SignedString(j.secret)
}

/*
validateTokenAndGetSubject validates a JWT token and returns the subject.

If the token is invalid or expired, the function will return an error.
*/
func (j *JWT) validateTokenAndGetSubject(token string) (string, error) {
	t, err := jwt.Parse(token, func(t *jwt.Token) (interface{}, error) {
		return j.secret, nil
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

/*
Middleware is a middleware that validates a JWT token and
sets the subject to the context.

The Authorization header must be in the format "Bearer <token>".
If the token is invalid or expired, the middleware will return a 401 Unauthorized status.
If the token is valid, the subject will be set to the context.
*/
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
		subject, err := j.validateTokenAndGetSubject(token)
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

/*
GetSubjectFromGinContext gets the subject from the gin context.

If the subject is not set, the function will return an empty string.
*/
func (j *JWT) GetSubjectFromGinContext(c *gin.Context) string {
	subject, ok := c.Get("subject")
	if !ok {
		return ""
	}
	return subject.(string)
}
