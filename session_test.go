package main

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestValidateSessionAbsoluteExpiryRejectsOldSession(t *testing.T) {
	setupTestDB(t)

	token := createSession("alice", nil)
	if token == "" {
		t.Fatalf("expected session token")
	}
	now := time.Now().Unix()
	old := now - int64(maxSessionAbsoluteLifetime.Seconds()) - 60
	if _, err := db.Exec("UPDATE sessions SET created_at=?, expires=? WHERE token=?", old, now+86400, token); err != nil {
		t.Fatalf("update session: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	req.RemoteAddr = "127.0.0.1:1234"

	if _, ok := validateSession(req); ok {
		t.Fatalf("expected session to be rejected due to absolute expiry")
	}
}

func TestValidateSessionAbsoluteExpiryAcceptsNewSession(t *testing.T) {
	setupTestDB(t)

	token := createSession("alice", nil)
	if token == "" {
		t.Fatalf("expected session token")
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: token})
	req.RemoteAddr = "127.0.0.1:1234"

	if _, ok := validateSession(req); !ok {
		t.Fatalf("expected session to be valid")
	}
}
