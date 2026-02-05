package main

import (
	"crypto/tls"
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

func TestEncryptWalletPrivateKeyRoundTrip(t *testing.T) {
	t.Setenv(walletKeyEnvName, "wallet-secret")

	enc, err := encryptWalletPrivateKey("plain-key")
	if err != nil {
		t.Fatalf("encrypt: %v", err)
	}
	if !strings.HasPrefix(enc, walletKeyPrefix) {
		t.Fatalf("expected encrypted key prefix, got %q", enc)
	}
	dec, err := decryptWalletPrivateKey(enc)
	if err != nil {
		t.Fatalf("decrypt: %v", err)
	}
	if dec != "plain-key" {
		t.Fatalf("expected round-trip key, got %q", dec)
	}
}

func TestMigrateWalletPrivateKeys(t *testing.T) {
	t.Setenv(walletKeyEnvName, "wallet-secret")
	setupTestDB(t)

	if _, err := db.Exec("INSERT INTO wallets (address, private_key, status, assigned_to) VALUES ('T123', 'plain-key', 'Free', '')"); err != nil {
		t.Fatalf("insert wallet: %v", err)
	}

	migrateWalletPrivateKeys()

	if _, ok := walletEncryptionKey(); !ok {
		t.Fatalf("expected wallet encryption key to be set")
	}

	var stored string
	if err := db.QueryRow("SELECT private_key FROM wallets WHERE address='T123'").Scan(&stored); err != nil {
		t.Fatalf("query wallet: %v", err)
	}
	if !strings.HasPrefix(stored, walletKeyPrefix) {
		t.Fatalf("expected encrypted wallet key, got %q", stored)
	}
	dec, err := decryptWalletPrivateKey(stored)
	if err != nil {
		t.Fatalf("decrypt migrated key: %v", err)
	}
	if dec != "plain-key" {
		t.Fatalf("expected migrated key to decrypt to original, got %q", dec)
	}
}

func TestIsSecureRequest(t *testing.T) {
	origTrustProxy := cfg.TrustProxy
	origForceSecure := cfg.ForceSecureCookies
	t.Cleanup(func() {
		cfg.TrustProxy = origTrustProxy
		cfg.ForceSecureCookies = origForceSecure
	})

	tests := []struct {
		name        string
		trustProxy  bool
		forceSecure bool
		withTLS     bool
		forwarded   string
		xfp         string
		wantSecure  bool
	}{
		{
			name:       "direct tls",
			withTLS:    true,
			wantSecure: true,
		},
		{
			name:       "proxy trusted xfp https",
			trustProxy: true,
			xfp:        "https",
			wantSecure: true,
		},
		{
			name:       "proxy untrusted xfp https",
			trustProxy: false,
			xfp:        "https",
			wantSecure: false,
		},
		{
			name:        "force secure cookies",
			forceSecure: true,
			wantSecure:  true,
		},
		{
			name:       "proxy trusted forwarded proto https",
			trustProxy: true,
			forwarded:  "for=192.0.2.1;proto=https;host=example.com",
			wantSecure: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg.TrustProxy = tt.trustProxy
			cfg.ForceSecureCookies = tt.forceSecure

			req := httptest.NewRequest(http.MethodGet, "http://example.com", nil)
			if tt.withTLS {
				req.TLS = &tls.ConnectionState{}
			}
			if tt.forwarded != "" {
				req.Header.Set("Forwarded", tt.forwarded)
			}
			if tt.xfp != "" {
				req.Header.Set("X-Forwarded-Proto", tt.xfp)
			}

			if got := isSecureRequest(req); got != tt.wantSecure {
				t.Fatalf("expected secure=%v, got %v", tt.wantSecure, got)
			}
		})
	}
}
