package twofactor

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"os"
	"time"

	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
)

// Generate creates a new TOTP secret.
func Generate(username string) (*otp.Key, error) {
	return totp.Generate(totp.GenerateOpts{
		Issuer:      "2FA DevSecOps",
		AccountName: username,
		Period:      30,
		Digits:      otp.DigitsSix,
		Algorithm:   otp.AlgorithmSHA1,
	})
}

// Verify checks a six-digit TOTP code.
func Verify(secret, code string) bool {
	return totp.Validate(code, secret)
}

// Encrypt protects the secret using AES-256-GCM.
func Encrypt(secret string) (string, error) {
	block, err := encryptionBlock()
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}

	ciphertext := gcm.Seal(
		nonce, nonce, []byte(secret), nil,
	)

	return base64.StdEncoding.EncodeToString(ciphertext), nil
}

// Decrypt restores a previously encrypted secret.
func Decrypt(encoded string) (string, error) {
	block, err := encryptionBlock()
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	data, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(data) < nonceSize {
		return "", errors.New("invalid encrypted data")
	}

	nonce := data[:nonceSize]
	ciphertext := data[nonceSize:]

	plaintext, err := gcm.Open(
		nil, nonce, ciphertext, nil,
	)
	if err != nil {
		return "", err
	}

	return string(plaintext), nil
}

func encryptionBlock() (cipher.Block, error) {
	encoded := os.Getenv("TOTP_ENCRYPTION_KEY")

	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}

	if len(key) != 32 {
		return nil, errors.New(
			"TOTP_ENCRYPTION_KEY must contain 32 bytes",
		)
	}

	return aes.NewCipher(key)
}

// CurrentStep returns the current 30-second TOTP window.
func CurrentStep() int64 {
	return time.Now().Unix() / 30
}

func CurrentTime() time.Time {
	return time.Now()
}
