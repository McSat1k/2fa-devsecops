package main

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"html/template"
	"log"
	"net/http"
	"net/url"
	"os"
	"regexp"
	"time"

	"example.com/2fa-devsecops/internal/twofactor"
	"github.com/pquerna/otp"
	"github.com/pquerna/otp/totp"
	"github.com/skip2/go-qrcode"
)

var sixDigits = regexp.MustCompile(`^[0-9]{6}$`)

type twoFAView struct {
	Username string
	QRCode   template.URL
	Error    string
}

func sameOrigin(r *http.Request) bool {
	expectedScheme := "http"
	if r.TLS != nil {
		expectedScheme = "https"
	}

	expectedOrigin := expectedScheme + "://" + r.Host

	origin := r.Header.Get("Origin")
	if origin != "" {
		return origin == expectedOrigin
	}

	referer := r.Header.Get("Referer")
	if referer == "" {
		return false
	}

	u, err := url.Parse(referer)
	if err != nil {
		return false
	}

	return u.Scheme == expectedScheme &&
		u.Host == r.Host
}

func sessionTokenHash(r *http.Request) (string, error) {
	c, err := r.Cookie("session")
	if err != nil {
		return "", err
	}

	h := sha256.Sum256([]byte(c.Value))
	return hex.EncodeToString(h[:]), nil
}

func recordFailedAttempt(r *http.Request) {
	hash, err := sessionTokenHash(r)
	if err != nil {
		return
	}

	_, _ = db.Exec(`
		INSERT INTO totp_attempts (token_hash, attempts)
		VALUES (?, 1)
		ON CONFLICT(token_hash)
		DO UPDATE SET attempts = attempts + 1
	`, hash)
}

func tooManyAttempts(r *http.Request) bool {
	hash, err := sessionTokenHash(r)
	if err != nil {
		return true
	}

	var attempts int
	err = db.QueryRow(
		"SELECT attempts FROM totp_attempts WHERE token_hash = ?",
		hash,
	).Scan(&attempts)

	return err == nil && attempts >= 5
}

func validateTOTP(secret, code string) bool {
	if !sixDigits.MatchString(code) {
		return false
	}

	valid, err := totp.ValidateCustom(
		code,
		secret,
		time.Now(),
		totp.ValidateOpts{
			Period:    30,
			Skew:      1,
			Digits:    otp.DigitsSix,
			Algorithm: otp.AlgorithmSHA1,
		},
	)

	if err != nil {
		log.Printf("TOTP validation error: %v", err)
		return false
	}

	return valid
}

func setup2FAHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet &&
		r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}

	session, err := getAuthSession(r)
	if err != nil || session.AuthLevel != 1 {
		http.Redirect(w, r, "/login", 303)
		return
	}

	username, encrypted, enabled, err := getUser2FA(session.UserID)
	if err != nil {
		http.Error(w, "Database error", 500)
		return
	}

	if enabled {
		http.Redirect(w, r, "/verify-2fa", 303)
		return
	}

	// Generate the secret only once.
	if encrypted == "" {
		key, err := twofactor.Generate(username)
		if err != nil {
			http.Error(w, "TOTP generation error", 500)
			return
		}

		encrypted, err = twofactor.Encrypt(key.Secret())
		if err != nil {
			http.Error(w, "Encryption error", 500)
			return
		}

		_, err = db.Exec(`
			UPDATE users SET totp_secret = ?
			WHERE id = ? AND totp_enabled = 0
			AND (totp_secret IS NULL OR totp_secret = '')
		`, encrypted, session.UserID)
		if err != nil {
			http.Error(w, "Database error", 500)
			return
		}

		_, encrypted, _, err = getUser2FA(session.UserID)
		if err != nil {
			http.Error(w, "Database error", 500)
			return
		}
	}

	secret, err := twofactor.Decrypt(encrypted)
	if err != nil {
		http.Error(w, "Cannot decrypt TOTP secret", 500)
		return
	}

	if r.Method == http.MethodPost {
		if !sameOrigin(r) {
			http.Error(w, "Invalid origin", 403)
			return
		}

		if tooManyAttempts(r) {
			http.Error(w, "Too many attempts. Log in again later.", 429)
			return
		}

		r.Body = http.MaxBytesReader(w, r.Body, 4096)
		if err := r.ParseForm(); err != nil {
			http.Error(w, "Invalid form", 400)
			return
		}

		code := r.FormValue("code")

		if !validateTOTP(secret, code) {
			recordFailedAttempt(r)
			http.Error(w, "Invalid TOTP code", 401)
			return
		}

		step := time.Now().Unix() / 30

		result, err := db.Exec(`
			UPDATE users
			SET totp_enabled = 1, totp_last_step = ?
			WHERE id = ? AND totp_enabled = 0
			AND totp_last_step < ?
		`, step, session.UserID, step)

		if err != nil {
			http.Error(w, "Database error", 500)
			return
		}

		affected, err := result.RowsAffected()
		if err != nil || affected != 1 {
			http.Error(w, "Code already used or setup completed", 409)
			return
		}

		if err := createAuthSession(w, r, session.UserID, 2); err != nil {
			http.Error(w, "Session error", 500)
			return
		}

		http.Redirect(w, r, "/dashboard", 303)
		return
	}

	// Build the Google Authenticator provisioning URL.
	keyURL := (&url.URL{
		Scheme: "otpauth",
		Host:   "totp",
		Path:   "2FA DevSecOps:" + username,
		RawQuery: url.Values{
			"secret":    {secret},
			"issuer":    {"2FA DevSecOps"},
			"algorithm": {"SHA1"},
			"digits":    {"6"},
			"period":    {"30"},
		}.Encode(),
	}).String()

	png, err := qrcode.Encode(keyURL, qrcode.Medium, 256)
	if err != nil {
		http.Error(w, "QR generation error", 500)
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set(
		"Content-Security-Policy",
		"default-src 'none'; img-src data:; style-src 'unsafe-inline'; form-action 'self'; base-uri 'none'",
	)

	render(w, "setup-2fa.html", twoFAView{
		Username: username,
		QRCode: template.URL(
			"data:image/png;base64," +
				base64.StdEncoding.EncodeToString(png),
		),
	})
}

func verify2FAHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet &&
		r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}

	session, err := getAuthSession(r)
	if err != nil || session.AuthLevel != 1 {
		http.Redirect(w, r, "/login", 303)
		return
	}

	username, encrypted, enabled, err := getUser2FA(session.UserID)
	if err != nil {
		http.Error(w, "Database error", 500)
		return
	}

	if !enabled {
		http.Redirect(w, r, "/setup-2fa", 303)
		return
	}

	if r.Method == http.MethodGet {
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Referrer-Policy", "same-origin")

		render(w, "verify-2fa.html", twoFAView{
			Username: username,
		})
		return
	}

	if !sameOrigin(r) {
		http.Error(w, "Invalid origin", 403)
		return
	}

	if tooManyAttempts(r) {
		http.Error(w, "Too many attempts. Log in again later.", 429)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", 400)
		return
	}

	secret, err := twofactor.Decrypt(encrypted)
	if err != nil {
		http.Error(w, "Decryption error", 500)
		return
	}

	code := r.FormValue("code")
	if !validateTOTP(secret, code) {
		recordFailedAttempt(r)
		http.Error(w, "Invalid TOTP code", 401)
		return
	}

	step := time.Now().Unix() / 30

	// Prevent reuse of an accepted TOTP time step.
	result, err := db.Exec(`
		UPDATE users SET totp_last_step = ?
		WHERE id = ? AND totp_enabled = 1
		AND totp_last_step < ?
	`, step, session.UserID, step)

	if err != nil {
		http.Error(w, "Database error", 500)
		return
	}

	affected, err := result.RowsAffected()
	if err != nil || affected != 1 {
		http.Error(w, "TOTP code already used", 409)
		return
	}

	if err := createAuthSession(w, r, session.UserID, 2); err != nil {
		http.Error(w, "Session error", 500)
		return
	}

	http.Redirect(w, r, "/dashboard", 303)
}

// Create the table for tracking failed attempts.
func migrateTOTPAttempts() error {
	_, err := db.Exec(`
		CREATE TABLE IF NOT EXISTS totp_attempts (
			token_hash TEXT PRIMARY KEY,
			attempts INTEGER NOT NULL DEFAULT 0
		)
	`)
	return err
}

// Validate the encryption key at startup.
func checkTOTPKey() error {
	encoded := os.Getenv("TOTP_ENCRYPTION_KEY")

	key, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return err
	}

	if len(key) != 32 {
		return errors.New(
			"TOTP_ENCRYPTION_KEY must contain exactly 32 bytes",
		)
	}

	return nil
}
