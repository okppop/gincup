package gincup

import (
	"errors"

	"golang.org/x/crypto/bcrypt"
)

var (
	ErrBcryptEmptyString = errors.New("string is empty")
)

/*
BcryptHash hashes a string using bcrypt.

If the string is empty, the function will return an error.

The cost of the hash is 8, the hash will be 60 characters long.
*/
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

/*
BcryptVerify verifies a string against a bcrypt hash.

If the hash or the original string is empty, the function will return an error.
*/
func BcryptVerify(hashed, original string) error {
	if hashed == "" || original == "" {
		return ErrBcryptEmptyString
	}

	return bcrypt.CompareHashAndPassword([]byte(hashed), []byte(original))
}
