package gincup

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrBcryptEmptyString = errors.New("string is empty")
)

func BcryptHash(s string) (string, error) {
	if s == "" {
		return "", ErrBcryptEmptyString
	}

	data, err := bcrypt.GenerateFromPassword([]byte(s), 8)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func BcryptVerify(hashed, original string) error {
	if hashed == "" || original == "" {
		return ErrBcryptEmptyString
	}

	return bcrypt.CompareHashAndPassword([]byte(hashed), []byte(original))
}
