package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func TestValidateCSRFForm(t *testing.T) {
	token := "csrf-token"
	body := url.Values{"csrf_token": {token}}.Encode()
	req := httptest.NewRequest("POST", "/submit", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: token})

	if !validateCSRF(req) {
		t.Fatalf("expected CSRF validation to pass")
	}
}

func TestValidateCSRFHeader(t *testing.T) {
	token := "csrf-token"
	req := httptest.NewRequest("POST", "/submit", nil)
	req.Header.Set("X-CSRF-Token", token)
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: token})

	if !validateCSRF(req) {
		t.Fatalf("expected CSRF validation to pass with header token")
	}
}

func TestValidateCSRFInvalid(t *testing.T) {
	req := httptest.NewRequest("POST", "/submit", nil)
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "cookie"})

	if validateCSRF(req) {
		t.Fatalf("expected CSRF validation to fail without token")
	}
}

func TestInitialAdminPasswordFromEnv(t *testing.T) {
	const expected = "super-secret"
	t.Setenv("TITAN_ADMIN_PASSWORD", expected)

	pass, fromEnv := initialAdminPassword()
	if pass != expected {
		t.Fatalf("expected env password %q, got %q", expected, pass)
	}
	if !fromEnv {
		t.Fatalf("expected fromEnv to be true")
	}
}
