package main

import (
	"net/http"
	"strings"
	"time"
)

const sessionCookieName = "sess"
const maxSessionAbsoluteLifetime = 12 * time.Hour

func setSessionCookie(w http.ResponseWriter, r *http.Request, token string, maxAge int) {
	// Allow local development over HTTP (otherwise Secure cookies won't be sent).
	secure := isSecureRequest(r)
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteStrictMode,
		MaxAge:   maxAge,
	})
}

func createSession(username string, r *http.Request) string {
	token := generateToken() + generateToken()
	csrfToken := ""
	if r != nil {
		if c, err := r.Cookie(csrfCookieName); err == nil && c.Value != "" {
			csrfToken = c.Value
		}
	}
	if csrfToken == "" {
		csrfToken = generateToken()
	}
	now := time.Now().Unix()
	exp := now + 86400
	userAgent := ""
	ip := ""
	if r != nil {
		userAgent = r.UserAgent()
		ip = getIP(r)
	}
	// Backward compatible: if the table doesn't have new columns yet, this INSERT will fail.
	// Our db migration adds the columns; in case of older DB, fallback to the simple insert.
	if _, err := db.Exec("INSERT INTO sessions (token, username, expires, created_at, last_seen, user_agent, ip, csrf_token) VALUES (?, ?, ?, ?, ?, ?, ?, ?)", token, username, exp, now, now, userAgent, ip, csrfToken); err != nil {
		if _, err2 := db.Exec("INSERT INTO sessions (token, username, expires) VALUES (?, ?, ?)", token, username, exp); err2 != nil {
			return ""
		}
	}
	return token
}

func rotateSessionCSRF(sessionToken string) string {
	if sessionToken == "" {
		return ""
	}
	newToken := generateToken()
	if newToken == "" {
		return ""
	}
	if _, err := db.Exec("UPDATE sessions SET csrf_token=? WHERE token=? AND expires > ?", newToken, sessionToken, time.Now().Unix()); err != nil {
		return ""
	}
	return newToken
}

func getSessionCSRFToken(sessionToken string) (string, bool) {
	if sessionToken == "" {
		return "", false
	}
	var token string
	if err := db.QueryRow("SELECT csrf_token FROM sessions WHERE token=? AND expires > ?", sessionToken, time.Now().Unix()).Scan(&token); err != nil {
		return "", false
	}
	if token == "" {
		return "", false
	}
	return token, true
}

func getOrCreateSessionCSRFToken(sessionToken string) (string, bool) {
	token, ok := getSessionCSRFToken(sessionToken)
	if ok {
		return token, true
	}
	if sessionToken == "" {
		return "", false
	}
	newToken := generateToken()
	if newToken == "" {
		return "", false
	}
	if _, err := db.Exec("UPDATE sessions SET csrf_token=? WHERE token=? AND expires > ?", newToken, sessionToken, time.Now().Unix()); err != nil {
		return "", false
	}
	return newToken, true
}

func validateSession(r *http.Request) (string, bool) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return "", false
	}

	now := time.Now().Unix()
	var username string
	var createdAt int64
	err = db.QueryRow("SELECT username, COALESCE(created_at, 0) FROM sessions WHERE token=? AND expires > ?", c.Value, now).Scan(&username, &createdAt)
	if err != nil {
		if strings.Contains(err.Error(), "no such column") {
			if err = db.QueryRow("SELECT username FROM sessions WHERE token=? AND expires > ?", c.Value, now).Scan(&username); err != nil {
				return "", false
			}
		} else {
			return "", false
		}
	} else if createdAt > 0 && now-createdAt > int64(maxSessionAbsoluteLifetime.Seconds()) {
		return "", false
	}

	// Best-effort last_seen update (ignore errors if column doesn't exist)
	userAgent := ""
	ip := ""
	if r != nil {
		userAgent = r.UserAgent()
		ip = getIP(r)
	}
	_, _ = db.Exec("UPDATE sessions SET last_seen=?, user_agent=?, ip=? WHERE token=?", now, userAgent, ip, c.Value)

	return username, true
}

func isRateLimited(ip string) bool {
	limiterMu.Lock()
	defer limiterMu.Unlock()

	now := time.Now().Unix()
	entry, exists := rateLimiter[ip]

	if !exists || now-entry.LastReset > 10 {
		rateLimiter[ip] = &RateLimitEntry{Count: 1, LastReset: now}
		return false
	}

	entry.Count++
	if entry.Count > 10 {
		return true
	}
	return false
}
