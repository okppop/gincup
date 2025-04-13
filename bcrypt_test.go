package gincup

import (
	"errors"
	"testing"
)

func TestBcrypt(t *testing.T) {
	t.Run("hash and verify", func(t *testing.T) {
		hashed, err := BcryptHash("password")
		if err != nil {
			t.Fatal(err)
		}

		err = BcryptVerify(hashed, "password")
		if err != nil {
			t.Fatal(err)
		}

		err = BcryptVerify(hashed, "wrong password")
		if err == nil {
			t.Fatal("should return error")
		}

		t.Run("empty password", func(t *testing.T) {
			_, err := BcryptHash("")
			if err == nil {
				t.Fatal("should return error")
			}

			if !errors.Is(err, ErrBcryptEmptyString) {
				t.Fatal("should return ErrBcryptEmptyString")
			}
		})
	})
}
