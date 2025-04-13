package gincup

import (
	"testing"
	"time"
)

func TestJWT(t *testing.T) {
	t.Run("normal web token", func(t *testing.T) {
		j := NewJWT("secret", 1*time.Hour)

		token, err := j.GenerateToken("123")
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

		token, err := j.GenerateToken("123")
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
