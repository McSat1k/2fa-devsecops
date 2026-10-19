package main

import (
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"html/template"
	"log"
	"net/http"
	"os"
	"strings"

	"golang.org/x/crypto/bcrypt"
	_ "modernc.org/sqlite"
)

var db *sql.DB

func main() {
	var err error

	dbPath := os.Getenv("DB_PATH")
	if dbPath == "" {
		dbPath = "users.db"
	}

	db, err = sql.Open("sqlite", dbPath)
	if err != nil {
		log.Fatal(err)
	}
	defer db.Close()

	db.SetMaxOpenConns(1)

	_, err = db.Exec(`
		CREATE TABLE IF NOT EXISTS users (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			username TEXT NOT NULL UNIQUE,
			password_hash TEXT NOT NULL
		);

		CREATE TABLE IF NOT EXISTS sessions (
			token_hash TEXT PRIMARY KEY,
			user_id INTEGER NOT NULL,
			expires_at INTEGER NOT NULL,
			FOREIGN KEY(user_id) REFERENCES users(id)
		);
	`)
	if err != nil {
		log.Fatal(err)
	}

	if err := migrateTwoFactor(); err != nil {
		log.Fatal("2FA database migration failed: ", err)
	}

	log.Println("2FA database migration completed")

	// Миграция сессий для двухфакторной аутентификации
	if err := migrateAuthSessions(); err != nil {
		log.Fatal("Session migration failed: ", err)
	}

	log.Println("Session migration completed")

	if err := checkTOTPKey(); err != nil {
		log.Fatal("Invalid TOTP_ENCRYPTION_KEY: ", err)
	}

	if err := migrateTOTPAttempts(); err != nil {
		log.Fatal("TOTP attempts migration failed: ", err)
	}

	log.Println("TOTP initialization completed")

	mux := http.NewServeMux()

	mux.HandleFunc("/", homeHandler)
	mux.HandleFunc("/register", registerHandler)
	mux.HandleFunc("/login", loginHandler)
	mux.HandleFunc("/setup-2fa", setup2FAHandler)
	mux.HandleFunc("/verify-2fa", verify2FAHandler)
	mux.HandleFunc("/dashboard", dashboardHandler)
	mux.HandleFunc("/logout", logoutHandler)
	mux.HandleFunc("/health", healthHandler)

	log.Println("Server running: http://localhost:8080")

	log.Fatal(http.ListenAndServe("0.0.0.0:8080", mux))

}

func render(w http.ResponseWriter, file string, data any) {
	t, err := template.ParseFiles("templates/" + file)
	if err != nil {
		log.Println(err)
		http.Error(w, "Template error", 500)
		return
	}

	w.Header().Set("Content-Type", "text/html; charset=utf-8")

	if err := t.Execute(w, data); err != nil {
		log.Println(err)
	}
}

func homeHandler(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}

	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", 405)
		return
	}

	render(w, "index.html", nil)
}

func registerHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		render(w, "register.html", nil)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", 400)
		return
	}

	username := strings.TrimSpace(r.FormValue("username"))
	password := r.FormValue("password")

	if len(username) < 3 || len(username) > 40 ||
		len(password) < 12 || len(password) > 72 {
		http.Error(w, "Username: 3-40 characters; password: 12-72 bytes", 400)
		return
	}

	hash, err := bcrypt.GenerateFromPassword(
		[]byte(password), bcrypt.DefaultCost,
	)
	if err != nil {
		http.Error(w, "Registration error", 500)
		return
	}

	_, err = db.Exec(
		"INSERT INTO users (username, password_hash) VALUES (?, ?)",
		username, string(hash),
	)
	if err != nil {
		http.Error(w, "Username unavailable", 409)
		return
	}

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodGet {
		render(w, "login.html", nil)
		return
	}

	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, 4096)
	if err := r.ParseForm(); err != nil {
		http.Error(w, "Invalid form", http.StatusBadRequest)
		return
	}

	username := r.FormValue("username")
	password := r.FormValue("password")

	var userID int64
	var passwordHash string

	err := db.QueryRow(
		"SELECT id, password_hash FROM users WHERE username = ?",
		username,
	).Scan(&userID, &passwordHash)

	if err != nil || bcrypt.CompareHashAndPassword(
		[]byte(passwordHash),
		[]byte(password),
	) != nil {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}

	// Пароль верный, но 2FA ещё не подтверждена.
	if err := createAuthSession(w, r, userID, 1); err != nil {
		http.Error(w, "Session error", http.StatusInternalServerError)
		return
	}

	_, _, enabled, err := getUser2FA(userID)
	if err != nil {
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	if enabled {
		http.Redirect(w, r, "/verify-2fa", http.StatusSeeOther)
	} else {
		http.Redirect(w, r, "/setup-2fa", http.StatusSeeOther)
	}
}

func dashboardHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	session, err := getAuthSession(r)

	// Личный кабинет доступен только после 2FA.
	if err != nil || session.AuthLevel != 2 {
		http.Redirect(w, r, "/login", http.StatusSeeOther)
		return
	}

	var username string

	err = db.QueryRow(
		"SELECT username FROM users WHERE id = ?",
		session.UserID,
	).Scan(&username)

	if err != nil {
		http.Error(w, "User not found", http.StatusNotFound)
		return
	}

	// Проверяем, подключена ли 2FA в базе данных.
	_, _, enabled, err := getUser2FA(session.UserID)
	if err != nil {
		log.Println("Failed to get 2FA status:", err)
		http.Error(w, "Database error", http.StatusInternalServerError)
		return
	}

	// Подготавливаем данные для HTML-шаблона.
	data := struct {
		Username     string
		TwoFAEnabled bool
	}{
		Username:     username,
		TwoFAEnabled: enabled,
	}

	w.Header().Set("Cache-Control", "no-store")
	render(w, "dashboard.html", data)
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Method not allowed", 405)
		return
	}

	// Strict SameSite plus Origin validation for logout.
	origin := r.Header.Get("Origin")
	if origin != "" {
		expected := "http://" + r.Host
		if r.TLS != nil {
			expected = "https://" + r.Host
		}
		if origin != expected {
			http.Error(w, "Invalid origin", 403)
			return
		}
	}

	if cookie, err := r.Cookie("session"); err == nil {
		hash := sha256.Sum256([]byte(cookie.Value))
		_, _ = db.Exec(
			"DELETE FROM sessions WHERE token_hash = ?",
			hex.EncodeToString(hash[:]),
		)
	}

	http.SetCookie(w, &http.Cookie{
		Name:     "session",
		Value:    "",
		Path:     "/",
		HttpOnly: true,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   -1,
		Secure:   r.TLS != nil,
	})

	http.Redirect(w, r, "/login", http.StatusSeeOther)
}

func healthHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.Error(w, "Method not allowed", 405)
		return
	}

	if err := db.Ping(); err != nil &&
		!errors.Is(err, sql.ErrNoRows) {
		http.Error(w, "Database unavailable", 503)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(
		map[string]string{"status": "ok"},
	)
}

func migrateTwoFactor() error {

	columns := []struct {
		name       string
		definition string
	}{
		{"totp_secret", "TEXT"},
		{"totp_enabled", "INTEGER NOT NULL DEFAULT 0"},
		{"totp_last_step", "INTEGER NOT NULL DEFAULT -1"},
	}

	for _, column := range columns {
		rows, err := db.Query("PRAGMA table_info(users)")
		if err != nil {
			return err
		}

		exists := false

		for rows.Next() {
			var cid int
			var name, dataType string
			var notNull, primaryKey int
			var defaultValue sql.NullString

			err := rows.Scan(
				&cid,
				&name,
				&dataType,
				&notNull,
				&defaultValue,
				&primaryKey,
			)
			if err != nil {
				rows.Close()
				return err
			}

			if name == column.name {
				exists = true
			}
		}

		if err := rows.Err(); err != nil {
			rows.Close()
			return err
		}

		rows.Close()

		if !exists {
			query := "ALTER TABLE users ADD COLUMN " +
				column.name + " " + column.definition

			if _, err := db.Exec(query); err != nil {
				return err
			}
		}
	}

	return nil
}
