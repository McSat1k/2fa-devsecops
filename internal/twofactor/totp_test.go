package twofactor

import (
	"testing"

	"github.com/pquerna/otp/totp"
)

func TestTOTP(t *testing.T) {
	key, err := Generate("testuser")
	if err != nil {
		t.Fatal(err)
	}

	code, err := totp.GenerateCode(
		key.Secret(),
		CurrentTime(),
	)
	if err != nil {
		t.Fatal(err)
	}

	if !Verify(key.Secret(), code) {
		t.Fatal("Valid TOTP code was rejected")
	}
}

func TestEncryption(t *testing.T) {
	secret := "EXAMPLESECRET123"

	encrypted, err := Encrypt(secret)
	if err != nil {
		t.Fatal(err)
	}

	if encrypted == secret {
		t.Fatal("Secret was not encrypted")
	}

	decrypted, err := Decrypt(encrypted)
	if err != nil {
		t.Fatal(err)
	}

	if decrypted != secret {
		t.Fatal("Decrypted secret does not match")
	}
}
