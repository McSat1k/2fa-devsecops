package main

import (
	"crypto/rand"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"errors"
	"net/http"
	"time"
)

type AuthSession struct {
	UserID    int64
	AuthLevel int
}

func createAuthSession(
	w http.ResponseWriter,
	r *http.Request,
	userID int64,
	authLevel int,
) error {
	tokenBytes := make([]byte, 32)

	if _, err := rand.Read(tokenBytes); err != nil {
		return err
	}

	token := hex.EncodeToString(tokenBytes)
	hash := sha256.Sum256([]byte(token))

	// Invalidate any existing session from this browser.
	if oldCookie, err := r.Cookie("session"); err == nil {
		oldHash := sha256.Sum256([]byte(oldCookie.Value))
		_, _ = db.Exec(
			"DELETE FROM sessions WHERE token_hash = ?",
			hex.EncodeToString(oldHash[:]),
		)
	}

	duration := 5 * time.Minute
	if authLevel == 2 {
		duration = 12 * time.Hour
	}

	expires := time.Now().Add(duration)

	_, err := db.Exec(`
		INSERT INTO sessions
		(token_hash, user_id, expires_at, auth_level)
		VALUES (?, ?, ?, ?)
	`,
		hex.EncodeToString(hash[:]),
		userID,
		expires.Unix(),
		authLevel,
	)
	if err != nil {
		return err
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		Secure:   r.TLS != nil,
		Expires:  expires,
	})

	return nil
}

func getAuthSession(r *http.Request) (AuthSession, error) {
	var session AuthSession

	cookie, err := r.Cookie("session")
	if err != nil {
		return session, err
	}

	hash := sha256.Sum256([]byte(cookie.Value))

	err = db.QueryRow(`
		SELECT user_id, auth_level
		FROM sessions
		WHERE token_hash = ?
		AND expires_at > ?
	`,
		hex.EncodeToString(hash[:]),
		time.Now().Unix(),
	).Scan(&session.UserID, &session.AuthLevel)

	if err != nil {
		return session, err
	}

	if session.AuthLevel != 1 && session.AuthLevel != 2 {
		return AuthSession{}, errors.New("invalid auth level")
	}

	return session, nil
}

func getUser2FA(userID int64) (
	string, string, bool, error,
) {
	var username string
	var encryptedSecret sql.NullString
	var enabled int

	err := db.QueryRow(`
		SELECT username, totp_secret, totp_enabled
		FROM users
		WHERE id = ?
	`, userID).Scan(
		&username,
		&encryptedSecret,
		&enabled,
	)

	return username, encryptedSecret.String, enabled == 1, err
}

func migrateAuthSessions() error {
	rows, err := db.Query("PRAGMA table_info(sessions)")
	if err != nil {
		return err
	}

	hasAuthLevel := false

	for rows.Next() {
		var cid, notNull, primaryKey int
		var name, dataType string
		var defaultValue sql.NullString

		if err := rows.Scan(
			&cid,
			&name,
			&dataType,
			&notNull,
			&defaultValue,
			&primaryKey,
		); err != nil {
			rows.Close()
			return err
		}

		if name == "auth_level" {
			hasAuthLevel = true
		}
	}

	if err := rows.Err(); err != nil {
		rows.Close()
		return err
	}
	rows.Close()

	if !hasAuthLevel {
		_, err = db.Exec(`
			ALTER TABLE sessions
			ADD COLUMN auth_level INTEGER NOT NULL DEFAULT 1
		`)
		if err != nil {
			return err
		}
	}

	return nil
}
