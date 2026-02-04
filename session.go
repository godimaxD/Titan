package main

import (
	"net/http"
	"time"
)

const sessionCookieName = "sess"

func setSessionCookie(w http.ResponseWriter, r *http.Request, token string, maxAge int) {
	// Allow local development over HTTP (otherwise Secure cookies won't be sent).
	secure := true
	if r != nil && r.TLS == nil {
		secure = false
	}
	http.SetCookie(w, &http.Cookie{
		Name:     sessionCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
		MaxAge:   maxAge,
	})
}

func createSession(username string, r *http.Request) string {
	token := generateToken() + generateToken()
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
	if _, err := db.Exec("INSERT INTO sessions (token, username, expires, created_at, last_seen, user_agent, ip) VALUES (?, ?, ?, ?, ?, ?, ?)", token, username, exp, now, now, userAgent, ip); err != nil {
		if _, err2 := db.Exec("INSERT INTO sessions (token, username, expires) VALUES (?, ?, ?)", token, username, exp); err2 != nil {
			return ""
		}
	}
	return token
}

func validateSession(r *http.Request) (string, bool) {
	c, err := r.Cookie(sessionCookieName)
	if err != nil {
		return "", false
	}

	var username string
	err = db.QueryRow("SELECT username FROM sessions WHERE token=? AND expires > ?", c.Value, time.Now().Unix()).Scan(&username)
	if err != nil {
		return "", false
	}

	// Best-effort last_seen update (ignore errors if column doesn't exist)
	now := time.Now().Unix()
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
