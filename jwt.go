package gincup

import (
	"errors"
	"strings"
	"time"

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
	token = strings.TrimPrefix(token, "Bearer ")

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
