package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"regexp"
	"strings"
	"testing"
	"time"
)

func setupTestDB(t *testing.T) {
	t.Helper()
	var err error
	db, err = sql.Open("sqlite3", "file::memory:?cache=shared")
	if err != nil {
		t.Fatalf("open db: %v", err)
	}
	if _, err := db.Exec("PRAGMA busy_timeout = 5000"); err != nil {
		t.Fatalf("set busy timeout: %v", err)
	}
	t.Cleanup(func() {
		_ = db.Close()
	})

	stmts := []string{
		`CREATE TABLE users (
			username TEXT PRIMARY KEY, password TEXT, plan TEXT, status TEXT, api_token TEXT, user_id TEXT, balance REAL DEFAULT 0,
			ref_code TEXT, referred_by TEXT, ref_earnings REAL DEFAULT 0, ref_paid INTEGER DEFAULT 0
		);`,
		`CREATE TABLE sessions (
			token TEXT PRIMARY KEY, username TEXT, expires INTEGER, created_at INTEGER, last_seen INTEGER, user_agent TEXT, ip TEXT
		);`,
		`CREATE TABLE products (
			id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, price REAL, time INTEGER, concurrents INTEGER, vip BOOLEAN, api_access BOOLEAN
		);`,
		`CREATE TABLE plans (name TEXT PRIMARY KEY, concurrents INTEGER, max_time INTEGER, vip BOOLEAN, api BOOLEAN);`,
		`CREATE TABLE redeem_codes (code TEXT PRIMARY KEY, plan TEXT, used BOOLEAN);`,
		`CREATE TABLE wallets (address TEXT PRIMARY KEY, private_key TEXT, status TEXT, assigned_to TEXT);`,
		`CREATE TABLE deposits (
			id TEXT PRIMARY KEY, user_id TEXT, amount REAL, address TEXT, status TEXT, date TEXT, expires INTEGER,
			usd_amount REAL DEFAULT 0, confirmed_at TEXT, txid TEXT, fee REAL DEFAULT 0, notes TEXT
		);`,
		`CREATE TABLE methods (name TEXT PRIMARY KEY, layer TEXT, command TEXT, enabled BOOLEAN DEFAULT 1, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);`,
		`CREATE TABLE blacklist (target TEXT PRIMARY KEY, reason TEXT, date TEXT);`,
		`CREATE TABLE idempotency_keys (key TEXT PRIMARY KEY, user_id TEXT, action TEXT, reference_id TEXT, created_at INTEGER);`,
		`CREATE TABLE referral_credits (
			purchase_key TEXT PRIMARY KEY,
			buyer TEXT,
			referrer TEXT,
			amount REAL,
			product_id INTEGER,
			created_at TEXT
		);`,
		`CREATE TABLE activity_logs (
			id INTEGER PRIMARY KEY AUTOINCREMENT,
			timestamp TEXT,
			ts_unix INTEGER,
			actor_type TEXT,
			actor_id TEXT,
			username TEXT,
			action TEXT,
			severity TEXT,
			request_id TEXT,
			ip TEXT,
			user_agent TEXT,
			message TEXT,
			resource_ids TEXT,
			metadata TEXT
		);`,
	}
	for _, stmt := range stmts {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatalf("create table: %v", err)
		}
	}

	rateLimiter = make(map[string]*RateLimitEntry)
}

func TestHandleLoginSuccess(t *testing.T) {
	setupTestDB(t)
	hash, err := generatePasswordHash("secret-pass")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES (?, ?, 'Free', 'Active', 'tok', 'u#1', 0, 'ref', '', 0, 0)", "alice", hash); err != nil {
		t.Fatalf("insert user: %v", err)
	}

	body := url.Values{
		"username":   {"alice"},
		"password":   {"secret-pass"},
		"csrf_token": {"csrf-token"},
	}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
	req.RemoteAddr = "127.0.0.1:1234"

	rr := httptest.NewRecorder()
	handleLogin(rr, req)

	res := rr.Result()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("expected redirect, got %d", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); !strings.HasPrefix(loc, "/dashboard") {
		t.Fatalf("expected dashboard redirect, got %q", loc)
	}
	if len(res.Cookies()) == 0 {
		t.Fatalf("expected session cookie")
	}
}

func TestHandleTokenLoginSuccess(t *testing.T) {
	setupTestDB(t)
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES (?, ?, 'Free', 'Active', ?, 'u#1', 0, 'ref', '', 0, 0)", "api-user", "hash", "api-token"); err != nil {
		t.Fatalf("insert user: %v", err)
	}

	body := url.Values{
		"token":      {"api-token"},
		"csrf_token": {"csrf-token"},
	}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/token-login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
	req.RemoteAddr = "127.0.0.1:1234"

	rr := httptest.NewRecorder()
	handleTokenLogin(rr, req)

	res := rr.Result()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("expected redirect, got %d", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); !strings.HasPrefix(loc, "/dashboard") {
		t.Fatalf("expected dashboard redirect, got %q", loc)
	}
	if len(res.Cookies()) == 0 {
		t.Fatalf("expected session cookie")
	}
}

func TestHandleTokenLoginInvalid(t *testing.T) {
	setupTestDB(t)
	body := url.Values{
		"token":      {""},
		"csrf_token": {"csrf-token"},
	}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/token-login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
	req.RemoteAddr = "127.0.0.1:1234"

	rr := httptest.NewRecorder()
	handleTokenLogin(rr, req)

	res := rr.Result()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("expected redirect, got %d", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); loc != "/login?err=invalid_token&mode=token" {
		t.Fatalf("expected invalid token redirect, got %q", loc)
	}
}

func TestHandlePurchaseSuccess(t *testing.T) {
	setupTestDB(t)
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('buyer', 'x', 'Free', 'Active', 'tok', 'u#2', 50, 'ref', '', 0, 0)"); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := db.Exec("INSERT INTO products (id, name, price, time, concurrents, vip, api_access) VALUES (1, 'Pro', 10, 60, 1, 0, 0)"); err != nil {
		t.Fatalf("insert product: %v", err)
	}

	sess := createSession("buyer", nil)
	if sess == "" {
		t.Fatalf("expected session token")
	}

	body := url.Values{"csrf_token": {"csrf-token"}}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/api/market/purchase?id=1", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess})

	rr := httptest.NewRecorder()
	handlePurchase(rr, req)

	if rr.Result().StatusCode != http.StatusFound {
		t.Fatalf("expected redirect, got %d", rr.Result().StatusCode)
	}
	if loc := rr.Result().Header.Get("Location"); loc != "/dashboard?msg=plan_activated" {
		t.Fatalf("unexpected redirect location: %q", loc)
	}
}

func TestHandleStatusPageLayout(t *testing.T) {
	setupTestDB(t)
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('viewer', 'x', 'Free', 'Active', 'tok', 'u#2', 0, 'ref', '', 0, 0)"); err != nil {
		t.Fatalf("insert user: %v", err)
	}

	sess := createSession("viewer", nil)
	if sess == "" {
		t.Fatalf("expected session token")
	}

	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess})
	rr := httptest.NewRecorder()
	handleStatusPage(rr, req)

	res := rr.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected ok, got %d", res.StatusCode)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "<aside") {
		t.Fatalf("expected sidebar layout in status page")
	}
	if !strings.Contains(body, "Network Status") || !strings.Contains(body, "Uptime") {
		t.Fatalf("expected status content to include uptime")
	}
}

func TestHandleAddWalletAdmin(t *testing.T) {
	setupTestDB(t)
	t.Setenv(walletKeyEnvName, "wallet-secret")
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('admin', 'x', 'God', 'Active', 'tok', 'u#0', 0, 'ref', '', 0, 0)"); err != nil {
		t.Fatalf("insert admin: %v", err)
	}

	sess := createSession("admin", nil)
	if sess == "" {
		t.Fatalf("expected session token")
	}

	body := url.Values{
		"csrf_token":  {"csrf-token"},
		"address":     {"T123"},
		"private_key": {"key"},
	}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/add-wallet", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess})

	rr := httptest.NewRecorder()
	handleAddWallet(rr, req)

	if rr.Result().StatusCode != http.StatusFound {
		t.Fatalf("expected redirect, got %d", rr.Result().StatusCode)
	}

	var count int
	if err := db.QueryRow("SELECT count(*) FROM wallets WHERE address='T123'").Scan(&count); err != nil {
		t.Fatalf("query wallet: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected wallet insert, got %d", count)
	}
}

func TestHandleRotateTokenInvalidatesOld(t *testing.T) {
	setupTestDB(t)
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('rotate-user', 'x', 'Free', 'Active', 'old-token', 'u#3', 0, 'ref', '', 0, 0)"); err != nil {
		t.Fatalf("insert user: %v", err)
	}

	sess := createSession("rotate-user", nil)
	if sess == "" {
		t.Fatalf("expected session token")
	}

	req := httptest.NewRequest(http.MethodPost, "/api/user/token/rotate", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess})
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
	req.Header.Set("X-CSRF-Token", "csrf-token")
	rr := httptest.NewRecorder()
	handleRotateToken(rr, req)

	res := rr.Result()
	if res.StatusCode != http.StatusOK {
		t.Fatalf("expected ok, got %d", res.StatusCode)
	}
	var payload struct {
		Status string `json:"status"`
		Token  string `json:"token"`
	}
	if err := json.NewDecoder(res.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Token == "" || payload.Token == "old-token" {
		t.Fatalf("expected new token")
	}
	if _, ok := getUserByToken("old-token"); ok {
		t.Fatalf("expected old token to be invalidated")
	}
	if _, ok := getUserByToken(payload.Token); !ok {
		t.Fatalf("expected new token to be valid")
	}
}

func TestHandleAddWalletAdminMissingKey(t *testing.T) {
	setupTestDB(t)
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('admin', 'x', 'God', 'Active', 'tok', 'u#0', 0, 'ref', '', 0, 0)"); err != nil {
		t.Fatalf("insert admin: %v", err)
	}

	sess := createSession("admin", nil)
	if sess == "" {
		t.Fatalf("expected session token")
	}

	body := url.Values{
		"csrf_token":  {"csrf-token"},
		"address":     {"T999"},
		"private_key": {"key"},
	}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/add-wallet", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess})

	rr := httptest.NewRecorder()
	handleAddWallet(rr, req)

	if rr.Result().StatusCode != http.StatusInternalServerError {
		t.Fatalf("expected status 500, got %d", rr.Result().StatusCode)
	}
	if !strings.Contains(rr.Body.String(), walletKeyEnvName) {
		t.Fatalf("expected error to mention %s", walletKeyEnvName)
	}

	var count int
	if err := db.QueryRow("SELECT count(*) FROM wallets WHERE address='T999'").Scan(&count); err != nil {
		t.Fatalf("query wallet: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected no wallet insert, got %d", count)
	}
}

func TestHandleAddWalletGetShowsEncryptionAlert(t *testing.T) {
	setupTestDB(t)
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('admin', 'x', 'God', 'Active', 'tok', 'u#0', 0, 'ref', '', 0, 0)"); err != nil {
		t.Fatalf("insert admin: %v", err)
	}

	sess := createSession("admin", nil)
	if sess == "" {
		t.Fatalf("expected session token")
	}

	req := httptest.NewRequest(http.MethodGet, "/api/admin/add-wallet", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess})

	rr := httptest.NewRecorder()
	handleAddWallet(rr, req)

	if rr.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Result().StatusCode)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "Manage Wallets") {
		t.Fatalf("expected admin wallet form to render")
	}
	if !strings.Contains(body, walletKeyEnvName) {
		t.Fatalf("expected alert to mention %s", walletKeyEnvName)
	}
	if !strings.Contains(body, "disabled") {
		t.Fatalf("expected submit button to be disabled")
	}
}

func TestPanelRequiresSession(t *testing.T) {
	setupTestDB(t)
	req := httptest.NewRequest(http.MethodGet, "/panel", nil)
	rr := httptest.NewRecorder()
	handlePage("panel.html")(rr, req)

	res := rr.Result()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("expected redirect, got %d", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); loc != "/login" {
		t.Fatalf("expected login redirect, got %q", loc)
	}
}

func TestPanelFormPagesRequireSession(t *testing.T) {
	setupTestDB(t)

	req := httptest.NewRequest(http.MethodGet, "/panel/l4", nil)
	rr := httptest.NewRecorder()
	handlePanelL4Page(rr, req)
	if rr.Result().StatusCode != http.StatusFound {
		t.Fatalf("expected redirect, got %d", rr.Result().StatusCode)
	}

	req = httptest.NewRequest(http.MethodGet, "/panel/l7", nil)
	rr = httptest.NewRecorder()
	handlePanelL7Page(rr, req)
	if rr.Result().StatusCode != http.StatusFound {
		t.Fatalf("expected redirect, got %d", rr.Result().StatusCode)
	}
}

func TestHandleRedeemLoginSuccess(t *testing.T) {
	setupTestDB(t)
	if _, err := db.Exec("INSERT INTO redeem_codes (code, plan, used) VALUES ('RDM123', 'Free', 0)"); err != nil {
		t.Fatalf("insert redeem code: %v", err)
	}

	body := url.Values{
		"redeem_code": {"RDM123"},
		"csrf_token":  {"csrf-token"},
	}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/redeem-login", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
	req.RemoteAddr = "127.0.0.1:1234"

	rr := httptest.NewRecorder()
	handleRedeemLogin(rr, req)

	res := rr.Result()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("expected redirect, got %d", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); !strings.HasPrefix(loc, "/dashboard") {
		t.Fatalf("expected dashboard redirect, got %q", loc)
	}
	foundSession := false
	for _, c := range res.Cookies() {
		if c.Name == sessionCookieName && c.Value != "" {
			foundSession = true
			break
		}
	}
	if !foundSession {
		t.Fatalf("expected session cookie")
	}

	var used bool
	if err := db.QueryRow("SELECT used FROM redeem_codes WHERE code='RDM123'").Scan(&used); err != nil {
		t.Fatalf("query redeem code: %v", err)
	}
	if !used {
		t.Fatalf("expected code to be marked used")
	}

	reqReuse := httptest.NewRequest(http.MethodPost, "/redeem-login", strings.NewReader(body))
	reqReuse.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	reqReuse.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
	reqReuse.RemoteAddr = "127.0.0.1:1234"
	rrReuse := httptest.NewRecorder()
	handleRedeemLogin(rrReuse, reqReuse)
	if loc := rrReuse.Result().Header.Get("Location"); loc != "/login?err=code_used&mode=redeem" {
		t.Fatalf("expected used code redirect, got %q", loc)
	}
}

func TestHandleRedeemLoginFailure(t *testing.T) {
	cases := []struct {
		name  string
		code  string
		setup func(t *testing.T)
	}{
		{
			name: "unknown code",
			code: "MISSING",
			setup: func(t *testing.T) {
				t.Helper()
			},
		},
		{
			name: "used code",
			code: "USED123",
			setup: func(t *testing.T) {
				t.Helper()
				if _, err := db.Exec("INSERT INTO redeem_codes (code, plan, used) VALUES ('USED123', 'Free', 1)"); err != nil {
					t.Fatalf("insert redeem code: %v", err)
				}
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setupTestDB(t)
			tc.setup(t)

			body := url.Values{
				"redeem_code": {tc.code},
				"csrf_token":  {"csrf-token"},
			}.Encode()
			req := httptest.NewRequest(http.MethodPost, "/redeem-login", strings.NewReader(body))
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
			req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
			req.RemoteAddr = "127.0.0.1:1234"

			rr := httptest.NewRecorder()
			handleRedeemLogin(rr, req)

			if tc.name == "used code" {
				if loc := rr.Result().Header.Get("Location"); loc != "/login?err=code_used&mode=redeem" {
					t.Fatalf("expected used code redirect, got %q", loc)
				}
			} else if loc := rr.Result().Header.Get("Location"); loc != "/login?err=invalid_code&mode=redeem" {
				t.Fatalf("expected invalid code redirect, got %q", loc)
			}
		})
	}
}

func TestLoginPageNoBackToLoginInPasswordMode(t *testing.T) {
	setupTestDB(t)
	req := httptest.NewRequest(http.MethodGet, "/login", nil)
	rr := httptest.NewRecorder()
	handleLogin(rr, req)

	if rr.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected OK, got %d", rr.Result().StatusCode)
	}
	body := rr.Body.String()
	if strings.Contains(body, "Back to Login") {
		t.Fatalf("expected no Back to Login link in password mode")
	}
	if !strings.Contains(body, "Login with Redeem Code") {
		t.Fatalf("expected redeem code option in login mode")
	}
}

func TestProfileCopyButtonMarkup(t *testing.T) {
	setupTestDB(t)
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('copy-user', 'x', 'Free', 'Active', 'tok-copy', 'u#9', 0, 'ref', '', 0, 0)"); err != nil {
		t.Fatalf("insert user: %v", err)
	}

	sess := createSession("copy-user", nil)
	if sess == "" {
		t.Fatalf("expected session token")
	}

	req := httptest.NewRequest(http.MethodGet, "/profile", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess})
	req.RemoteAddr = "127.0.0.1:1234"

	rr := httptest.NewRecorder()
	handlePage("profile.html")(rr, req)

	body := rr.Body.String()
	if !strings.Contains(body, "data-copy-target=\"api-token-value\"") {
		t.Fatalf("expected api token copy target")
	}
	if !strings.Contains(body, "navigator.clipboard") || !strings.Contains(body, "execCommand('copy')") {
		t.Fatalf("expected clipboard API with execCommand fallback")
	}
	if !strings.Contains(body, "Copied!") {
		t.Fatalf("expected copied feedback text")
	}
}

func TestProfileShowsApiTokenForSessionUser(t *testing.T) {
	cases := []struct {
		name        string
		sessionUser string
		expectToken string
		absentToken string
	}{
		{
			name:        "alice sees alice token",
			sessionUser: "alice",
			expectToken: "tok-alice",
			absentToken: "tok-bob",
		},
		{
			name:        "bob sees bob token",
			sessionUser: "bob",
			expectToken: "tok-bob",
			absentToken: "tok-alice",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			setupTestDB(t)
			if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('alice', 'x', 'Free', 'Active', 'tok-alice', 'u#1', 0, 'refa', '', 0, 0)"); err != nil {
				t.Fatalf("insert alice: %v", err)
			}
			if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('bob', 'x', 'Free', 'Active', 'tok-bob', 'u#2', 0, 'refb', '', 0, 0)"); err != nil {
				t.Fatalf("insert bob: %v", err)
			}

			sess := createSession(tc.sessionUser, nil)
			if sess == "" {
				t.Fatalf("expected session token")
			}

			req := httptest.NewRequest(http.MethodGet, "/profile", nil)
			req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess})
			req.RemoteAddr = "127.0.0.1:1234"

			rr := httptest.NewRecorder()
			handlePage("profile.html")(rr, req)

			body := rr.Body.String()
			if !strings.Contains(body, tc.expectToken) {
				t.Fatalf("expected token %q in response", tc.expectToken)
			}
			if strings.Contains(body, tc.absentToken) {
				t.Fatalf("did not expect token %q in response", tc.absentToken)
			}
		})
	}
}

func TestStatusPageShowsUptimeOnly(t *testing.T) {
	setupTestDB(t)
	startTime = time.Now().Add(-2 * time.Hour)
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('status-user', 'x', 'Free', 'Active', 'tok', 'u#9', 0, 'ref', '', 0, 0)"); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	sess := createSession("status-user", nil)
	if sess == "" {
		t.Fatalf("expected session token")
	}

	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess})
	req.RemoteAddr = "127.0.0.1:1234"
	rr := httptest.NewRecorder()
	handleStatusPage(rr, req)

	body := rr.Body.String()
	if !strings.Contains(body, "Uptime") {
		t.Fatalf("expected uptime label in response")
	}
	uptimeRe := regexp.MustCompile(`Uptime</div>\s*<div[^>]*>[^<]+</div>`)
	if !uptimeRe.MatchString(body) {
		t.Fatalf("expected non-empty uptime value")
	}

	lower := strings.ToLower(body)
	for _, keyword := range []string{"db", "wallet", "users", "runtime", "goroutine", "memory"} {
		if strings.Contains(lower, keyword) {
			t.Fatalf("did not expect keyword %q in status page", keyword)
		}
	}
}

func TestPanelL4SubmitRejectsMissingCSRF(t *testing.T) {
	setupTestDB(t)
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('alice', 'x', 'Free', 'Active', 'tok', 'u#1', 0, 'ref', '', 0, 0)"); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := db.Exec("INSERT INTO plans (name, concurrents, max_time, vip, api) VALUES ('Free', 2, 60, 0, 0)"); err != nil {
		t.Fatalf("insert plan: %v", err)
	}
	if _, err := db.Exec("INSERT INTO methods (name, layer, command, enabled) VALUES ('UDP-FLOOD', 'layer4', 'UDP-FLOOD', 1)"); err != nil {
		t.Fatalf("insert method: %v", err)
	}

	sess := createSession("alice", nil)
	body := url.Values{
		"target":      {"1.1.1.1"},
		"port":        {"80"},
		"time":        {"10"},
		"concurrency": {"1"},
		"method":      {"UDP-FLOOD"},
	}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/panel/l4/submit", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess})
	req.RemoteAddr = "127.0.0.1:1234"

	rr := httptest.NewRecorder()
	handlePanelL4Submit(rr, req)
	if rr.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Result().StatusCode)
	}
}

func TestHandleCreateDepositRedirectsToPayPage(t *testing.T) {
	setupTestDB(t)
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('alice', 'x', 'Free', 'Active', 'tok', 'u#1', 0, 'ref', '', 0, 0)"); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := db.Exec("INSERT INTO wallets (address, private_key, status, assigned_to) VALUES ('T123', 'key', 'Free', NULL)"); err != nil {
		t.Fatalf("insert wallet: %v", err)
	}
	cfg.BinanceAPI = "http://127.0.0.1:1"
	lastKnownTrxPrice = 0.2

	sess := createSession("alice", nil)
	body := url.Values{
		"csrf_token": {"csrf-token"},
		"amount":     {"25"},
	}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/api/deposit/create", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess})

	rr := httptest.NewRecorder()
	handleCreateDeposit(rr, req)

	res := rr.Result()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("expected redirect, got %d", res.StatusCode)
	}
	loc := res.Header.Get("Location")
	if !strings.HasPrefix(loc, "/deposit/pay?id=") {
		t.Fatalf("expected pay redirect, got %q", loc)
	}
}

func TestHandleCreateDepositAllowsEmptyStatusWallet(t *testing.T) {
	setupTestDB(t)
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('alice', 'x', 'Free', 'Active', 'tok', 'u#1', 0, 'ref', '', 0, 0)"); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := db.Exec("INSERT INTO wallets (address, private_key, status, assigned_to) VALUES ('TEMPTY', 'key', '', NULL)"); err != nil {
		t.Fatalf("insert wallet: %v", err)
	}
	cfg.BinanceAPI = "http://127.0.0.1:1"
	lastKnownTrxPrice = 0.2

	sess := createSession("alice", nil)
	body := url.Values{
		"csrf_token": {"csrf-token"},
		"amount":     {"10"},
	}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/api/deposit/create", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess})

	rr := httptest.NewRecorder()
	handleCreateDeposit(rr, req)

	if rr.Result().StatusCode != http.StatusFound {
		t.Fatalf("expected redirect, got %d", rr.Result().StatusCode)
	}
	if loc := rr.Result().Header.Get("Location"); !strings.HasPrefix(loc, "/deposit/pay?id=") {
		t.Fatalf("expected pay redirect, got %q", loc)
	}
}

func TestHandleCreateDepositReusesExpiredWallet(t *testing.T) {
	setupTestDB(t)
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('alice', 'x', 'Free', 'Active', 'tok', 'u#1', 0, 'ref', '', 0, 0)"); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := db.Exec("INSERT INTO wallets (address, private_key, status, assigned_to) VALUES ('TOLD', 'key', 'Busy', 'dep-old')"); err != nil {
		t.Fatalf("insert wallet: %v", err)
	}
	if _, err := db.Exec("INSERT INTO deposits (id, user_id, amount, usd_amount, address, status, date, expires) VALUES ('dep-old', 'alice', 10, 10, 'TOLD', 'Pending', '2024-01-01 12:00', ?)", time.Now().Add(-10*time.Minute).Unix()); err != nil {
		t.Fatalf("insert deposit: %v", err)
	}
	cfg.BinanceAPI = "http://127.0.0.1:1"
	lastKnownTrxPrice = 0.2

	sess := createSession("alice", nil)
	body := url.Values{
		"csrf_token": {"csrf-token"},
		"amount":     {"15"},
	}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/api/deposit/create", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess})

	rr := httptest.NewRecorder()
	handleCreateDeposit(rr, req)

	if rr.Result().StatusCode != http.StatusFound {
		t.Fatalf("expected redirect, got %d", rr.Result().StatusCode)
	}
	if loc := rr.Result().Header.Get("Location"); !strings.HasPrefix(loc, "/deposit/pay?id=") {
		t.Fatalf("expected pay redirect, got %q", loc)
	}
}

func TestHandleCreateDepositFailsWithNoUsableWallets(t *testing.T) {
	setupTestDB(t)
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('alice', 'x', 'Free', 'Active', 'tok', 'u#1', 0, 'ref', '', 0, 0)"); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	cfg.BinanceAPI = "http://127.0.0.1:1"
	lastKnownTrxPrice = 0.2

	sess := createSession("alice", nil)
	body := url.Values{
		"csrf_token": {"csrf-token"},
		"amount":     {"15"},
	}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/api/deposit/create", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess})

	rr := httptest.NewRecorder()
	handleCreateDeposit(rr, req)

	if rr.Result().StatusCode != http.StatusFound {
		t.Fatalf("expected redirect, got %d", rr.Result().StatusCode)
	}
	if loc := rr.Result().Header.Get("Location"); loc != "/deposit?err=wallets" {
		t.Fatalf("expected wallets error, got %q", loc)
	}
}

func TestHandleCreateDepositRollbackFreesWallet(t *testing.T) {
	setupTestDB(t)
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('alice', 'x', 'Free', 'Active', 'tok', 'u#1', 0, 'ref', '', 0, 0)"); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := db.Exec("INSERT INTO wallets (address, private_key, status, assigned_to) VALUES ('TROLL', 'key', 'Free', NULL)"); err != nil {
		t.Fatalf("insert wallet: %v", err)
	}
	if _, err := db.Exec(`CREATE TRIGGER fail_deposit_insert BEFORE INSERT ON deposits BEGIN SELECT RAISE(FAIL, 'boom'); END;`); err != nil {
		t.Fatalf("create trigger: %v", err)
	}
	cfg.BinanceAPI = "http://127.0.0.1:1"
	lastKnownTrxPrice = 0.2

	sess := createSession("alice", nil)
	body := url.Values{
		"csrf_token": {"csrf-token"},
		"amount":     {"20"},
	}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/api/deposit/create", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess})

	rr := httptest.NewRecorder()
	handleCreateDeposit(rr, req)

	if rr.Result().StatusCode != http.StatusFound {
		t.Fatalf("expected redirect, got %d", rr.Result().StatusCode)
	}
	if loc := rr.Result().Header.Get("Location"); loc != "/deposit?err=db" {
		t.Fatalf("expected db error, got %q", loc)
	}
	var status string
	var assigned sql.NullString
	if err := db.QueryRow("SELECT status, assigned_to FROM wallets WHERE address='TROLL'").Scan(&status, &assigned); err != nil {
		t.Fatalf("query wallet: %v", err)
	}
	if status != "Free" || assigned.Valid {
		t.Fatalf("expected wallet free and unassigned, got status=%q assigned=%v", status, assigned)
	}
}

func TestHandleCreateDepositRequiresCSRF(t *testing.T) {
	setupTestDB(t)
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('alice', 'x', 'Free', 'Active', 'tok', 'u#1', 0, 'ref', '', 0, 0)"); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	sess := createSession("alice", nil)
	req := httptest.NewRequest(http.MethodPost, "/api/deposit/create", strings.NewReader(url.Values{"amount": {"10"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess})

	rr := httptest.NewRecorder()
	handleCreateDeposit(rr, req)

	if rr.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("expected forbidden, got %d", rr.Result().StatusCode)
	}
}

func TestDepositPayPageRequiresSessionAndRenders(t *testing.T) {
	setupTestDB(t)
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('alice', 'x', 'Free', 'Active', 'tok', 'u#1', 0, 'ref', '', 0, 0)"); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO deposits (id, user_id, amount, usd_amount, address, status, date, expires) VALUES ('dep1', 'alice', 10, 25, 'TADDR', 'Pending', '2024-01-01 12:00', ?)`, time.Now().Add(10*time.Minute).Unix()); err != nil {
		t.Fatalf("insert deposit: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/deposit/pay?id=dep1", nil)
	rr := httptest.NewRecorder()
	handleDepositPayPage(rr, req)
	if rr.Result().StatusCode != http.StatusFound {
		t.Fatalf("expected redirect for missing session")
	}

	sess := createSession("alice", nil)
	req = httptest.NewRequest(http.MethodGet, "/deposit/pay?id=dep1", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess})
	rr = httptest.NewRecorder()
	handleDepositPayPage(rr, req)
	if rr.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected ok, got %d", rr.Result().StatusCode)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "TADDR") || !strings.Contains(body, "Waiting for payment") {
		t.Fatalf("expected pay page content")
	}
	if !strings.Contains(body, "/api/deposit/check") || !strings.Contains(body, "3000") {
		t.Fatalf("expected polling script")
	}
}

func TestDepositCheckOwnership(t *testing.T) {
	setupTestDB(t)
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('alice', 'x', 'Free', 'Active', 'tok', 'u#1', 0, 'ref', '', 0, 0)"); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('bob', 'x', 'Free', 'Active', 'tok', 'u#2', 0, 'ref', '', 0, 0)"); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO deposits (id, user_id, amount, usd_amount, address, status, date, expires) VALUES ('dep2', 'alice', 10, 25, 'TADDR', 'Pending', '2024-01-01 12:00', ?)`, time.Now().Add(10*time.Minute).Unix()); err != nil {
		t.Fatalf("insert deposit: %v", err)
	}

	sess := createSession("bob", nil)
	req := httptest.NewRequest(http.MethodGet, "/api/deposit/check?id=dep2", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess})
	rr := httptest.NewRecorder()
	handleCheckDeposit(rr, req)
	if rr.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("expected forbidden, got %d", rr.Result().StatusCode)
	}

	sess = createSession("alice", nil)
	req = httptest.NewRequest(http.MethodGet, "/api/deposit/check?id=dep2", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess})
	rr = httptest.NewRecorder()
	handleCheckDeposit(rr, req)
	if rr.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected ok, got %d", rr.Result().StatusCode)
	}
	var payload map[string]string
	if err := json.Unmarshal(rr.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload["status"] != "Pending" {
		t.Fatalf("expected Pending status, got %q", payload["status"])
	}
}

func TestStatusPageDoesNotLeakSensitiveInfo(t *testing.T) {
	setupTestDB(t)
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('status-user', 'x', 'Free', 'Active', 'tok', 'u#9', 0, 'ref', '', 0, 0)"); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	sess := createSession("status-user", nil)
	if sess == "" {
		t.Fatalf("expected session token")
	}
	req := httptest.NewRequest(http.MethodGet, "/status", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess})
	rr := httptest.NewRecorder()
	handleStatusPage(rr, req)

	if rr.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected ok, got %d", rr.Result().StatusCode)
	}
	body := strings.ToLower(rr.Body.String())
	for _, keyword := range []string{"goroutine", "mem", "sqlite", "wallet", "users", "sessions", "gomaxprocs", "runtime"} {
		if strings.Contains(body, keyword) {
			t.Fatalf("status page leaked keyword: %s", keyword)
		}
	}
}

func TestReceiptRequiresOwnershipAndDownloads(t *testing.T) {
	setupTestDB(t)
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('alice', 'x', 'Free', 'Active', 'tok', 'u#1', 0, 'ref', '', 0, 0)"); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := db.Exec(`INSERT INTO deposits (id, user_id, amount, usd_amount, address, status, date, expires, confirmed_at) VALUES ('dep3', 'alice', 10, 25, 'TADDR', 'Paid', '2024-01-01 12:00', ?, '2024-01-01 12:05')`, time.Now().Add(10*time.Minute).Unix()); err != nil {
		t.Fatalf("insert deposit: %v", err)
	}

	sess := createSession("alice", nil)
	req := httptest.NewRequest(http.MethodGet, "/receipt?id=dep3", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess})
	rr := httptest.NewRecorder()
	handleReceiptPage(rr, req)
	if rr.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected ok, got %d", rr.Result().StatusCode)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "dep3") || !strings.Contains(body, "TADDR") {
		t.Fatalf("expected receipt content")
	}

	req = httptest.NewRequest(http.MethodGet, "/receipt/download?id=dep3", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess})
	rr = httptest.NewRecorder()
	handleReceiptDownload(rr, req)
	if rr.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected ok, got %d", rr.Result().StatusCode)
	}
	if disp := rr.Result().Header.Get("Content-Disposition"); !strings.Contains(disp, "attachment") {
		t.Fatalf("expected attachment header")
	}
}

func TestPanelL7SubmitInvalidInput(t *testing.T) {
	setupTestDB(t)
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('bob', 'x', 'Free', 'Active', 'tok', 'u#2', 0, 'ref', '', 0, 0)"); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := db.Exec("INSERT INTO plans (name, concurrents, max_time, vip, api) VALUES ('Free', 2, 60, 0, 0)"); err != nil {
		t.Fatalf("insert plan: %v", err)
	}
	if _, err := db.Exec("INSERT INTO methods (name, layer, command, enabled) VALUES ('HTTP-GET', 'layer7', 'HTTP-GET', 1)"); err != nil {
		t.Fatalf("insert method: %v", err)
	}

	sess := createSession("bob", nil)
	body := url.Values{
		"target":      {"not-a-url"},
		"time":        {"10"},
		"concurrency": {"1"},
		"method":      {"HTTP-GET"},
		"csrf_token":  {"csrf-token"},
	}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/panel/l7/submit", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess})
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
	req.RemoteAddr = "127.0.0.1:1234"

	rr := httptest.NewRecorder()
	handlePanelL7Submit(rr, req)
	if rr.Result().StatusCode != http.StatusBadRequest {
		t.Fatalf("expected 400, got %d", rr.Result().StatusCode)
	}
}

func TestApiLaunchMethodNotAllowed(t *testing.T) {
	setupTestDB(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	origHost := cfg.C2Host
	origKey := cfg.C2Key
	cfg.C2Host = server.URL
	cfg.C2Key = "key"
	t.Cleanup(func() {
		cfg.C2Host = origHost
		cfg.C2Key = origKey
	})

	if _, err := db.Exec("INSERT INTO plans (name, concurrents, max_time, vip, api) VALUES ('Pro', 1, 60, 0, 1)"); err != nil {
		t.Fatalf("insert plan: %v", err)
	}
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('apiuser', 'x', 'Pro', 'Active', 'tok', 'u#1', 0, 'ref', '', 0, 0)"); err != nil {
		t.Fatalf("insert user: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/api/launch", nil)
	req.Header.Set("Authorization", "Bearer tok")
	req.RemoteAddr = "127.0.0.1:1234"
	rr := httptest.NewRecorder()
	apiLaunch(rr, req)
	if rr.Result().StatusCode != http.StatusMethodNotAllowed {
		t.Fatalf("expected method not allowed, got %d", rr.Result().StatusCode)
	}
}

func TestApiLaunchMissingAuth(t *testing.T) {
	setupTestDB(t)
	req := httptest.NewRequest(http.MethodPost, "/api/launch", strings.NewReader(url.Values{"target": {"1.1.1.1"}}.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "127.0.0.1:1234"
	rr := httptest.NewRecorder()
	apiLaunch(rr, req)
	if rr.Result().StatusCode != http.StatusUnauthorized {
		t.Fatalf("expected unauthorized, got %d", rr.Result().StatusCode)
	}
}

func TestApiLaunchRequiresAPIPlan(t *testing.T) {
	setupTestDB(t)
	if _, err := db.Exec("INSERT INTO plans (name, concurrents, max_time, vip, api) VALUES ('Free', 1, 60, 0, 0)"); err != nil {
		t.Fatalf("insert plan: %v", err)
	}
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('apiuser', 'x', 'Free', 'Active', 'tok', 'u#1', 0, 'ref', '', 0, 0)"); err != nil {
		t.Fatalf("insert user: %v", err)
	}

	req := httptest.NewRequest(http.MethodPost, "/api/launch", strings.NewReader(url.Values{"target": {"1.1.1.1"}}.Encode()))
	req.Header.Set("Authorization", "Bearer tok")
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.RemoteAddr = "127.0.0.1:1234"
	rr := httptest.NewRecorder()
	apiLaunch(rr, req)
	if rr.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("expected forbidden, got %d", rr.Result().StatusCode)
	}
}

func TestApiLaunchRateLimit(t *testing.T) {
	setupTestDB(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	origHost := cfg.C2Host
	origKey := cfg.C2Key
	cfg.C2Host = server.URL
	cfg.C2Key = "key"
	t.Cleanup(func() {
		cfg.C2Host = origHost
		cfg.C2Key = origKey
	})

	if _, err := db.Exec("INSERT INTO plans (name, concurrents, max_time, vip, api) VALUES ('Pro', 1, 60, 0, 1)"); err != nil {
		t.Fatalf("insert plan: %v", err)
	}
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('apiuser', 'x', 'Pro', 'Active', 'tok', 'u#1', 0, 'ref', '', 0, 0)"); err != nil {
		t.Fatalf("insert user: %v", err)
	}

	var lastStatus int
	for i := 0; i < 11; i++ {
		req := httptest.NewRequest(http.MethodPost, "/api/launch", strings.NewReader(url.Values{"target": {"1.1.1.1"}}.Encode()))
		req.Header.Set("Authorization", "Bearer tok")
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.RemoteAddr = "127.0.0.1:1234"
		rr := httptest.NewRecorder()
		apiLaunch(rr, req)
		lastStatus = rr.Result().StatusCode
	}
	if lastStatus != http.StatusTooManyRequests {
		t.Fatalf("expected rate limit status, got %d", lastStatus)
	}
}

func TestApiStopAllScope(t *testing.T) {
	setupTestDB(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(server.Close)
	origHost := cfg.C2Host
	origKey := cfg.C2Key
	cfg.C2Host = server.URL
	cfg.C2Key = "key"
	t.Cleanup(func() {
		cfg.C2Host = origHost
		cfg.C2Key = origKey
	})

	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('alice', 'x', 'Free', 'Active', 'tok', 'u#1', 0, 'ref', '', 0, 0)"); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('bob', 'x', 'Free', 'Active', 'tok2', 'u#2', 0, 'ref', '', 0, 0)"); err != nil {
		t.Fatalf("insert user: %v", err)
	}

	mu.Lock()
	activeAttacks = map[string]AttackData{
		"a1": {ID: "a1", UserID: "alice"},
		"b1": {ID: "b1", UserID: "bob"},
	}
	mu.Unlock()

	sess := createSession("alice", nil)
	req := httptest.NewRequest(http.MethodPost, "/api/attack/stopAll", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess})
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
	req.Header.Set("X-CSRF-Token", "csrf-token")
	rr := httptest.NewRecorder()
	apiStopAll(rr, req)
	if rr.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected ok, got %d", rr.Result().StatusCode)
	}
	mu.Lock()
	if len(activeAttacks) != 1 {
		mu.Unlock()
		t.Fatalf("expected one attack remaining, got %d", len(activeAttacks))
	}
	if _, ok := activeAttacks["b1"]; !ok {
		mu.Unlock()
		t.Fatalf("expected bob attack to remain")
	}
	mu.Unlock()

	mu.Lock()
	activeAttacks = map[string]AttackData{
		"a1": {ID: "a1", UserID: "alice"},
		"b1": {ID: "b1", UserID: "bob"},
	}
	mu.Unlock()

	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('admin', 'x', 'God', 'Active', 'tok3', 'u#0', 0, 'ref', '', 0, 0)"); err != nil {
		t.Fatalf("insert admin: %v", err)
	}
	sess = createSession("admin", nil)
	req = httptest.NewRequest(http.MethodPost, "/api/attack/stopAll", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess})
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
	req.Header.Set("X-CSRF-Token", "csrf-token")
	rr = httptest.NewRecorder()
	apiStopAll(rr, req)
	if rr.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected ok, got %d", rr.Result().StatusCode)
	}
	mu.Lock()
	if len(activeAttacks) != 0 {
		mu.Unlock()
		t.Fatalf("expected all attacks cleared, got %d", len(activeAttacks))
	}
	mu.Unlock()
}

func TestDepositConfirmRollbackOnFailure(t *testing.T) {
	setupTestDB(t)
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('admin', 'x', 'God', 'Active', 'tok', 'u#0', 0, 'ref', '', 0, 0)"); err != nil {
		t.Fatalf("insert admin: %v", err)
	}
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('alice', 'x', 'Free', 'Active', 'tok2', 'u#1', 0, 'ref', '', 0, 0)"); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := db.Exec("INSERT INTO deposits (id, user_id, amount, usd_amount, address, status, date, expires) VALUES ('dep1', 'alice', 10, 25, 'TADDR', 'Pending', '2024-01-01', ?)", time.Now().Add(10*time.Minute).Unix()); err != nil {
		t.Fatalf("insert deposit: %v", err)
	}
	if _, err := db.Exec("DROP TABLE wallets"); err != nil {
		t.Fatalf("drop wallets: %v", err)
	}

	sess := createSession("admin", nil)
	body := url.Values{"id": {"dep1"}, "action": {"confirm"}, "csrf_token": {"csrf-token"}}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/deposit/action", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess})
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
	rr := httptest.NewRecorder()
	handleDepositAction(rr, req)
	if rr.Result().StatusCode != http.StatusFound {
		t.Fatalf("expected redirect, got %d", rr.Result().StatusCode)
	}

	var status string
	if err := db.QueryRow("SELECT status FROM deposits WHERE id='dep1'").Scan(&status); err != nil {
		t.Fatalf("query deposit: %v", err)
	}
	if status != "Pending" {
		t.Fatalf("expected pending status after rollback, got %q", status)
	}
	var balance float64
	if err := db.QueryRow("SELECT balance FROM users WHERE username='alice'").Scan(&balance); err != nil {
		t.Fatalf("query balance: %v", err)
	}
	if balance != 0 {
		t.Fatalf("expected balance unchanged, got %v", balance)
	}
}

func TestDepositRejectRollbackOnFailure(t *testing.T) {
	setupTestDB(t)
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('admin', 'x', 'God', 'Active', 'tok', 'u#0', 0, 'ref', '', 0, 0)"); err != nil {
		t.Fatalf("insert admin: %v", err)
	}
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('alice', 'x', 'Free', 'Active', 'tok2', 'u#1', 0, 'ref', '', 0, 0)"); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := db.Exec("INSERT INTO deposits (id, user_id, amount, usd_amount, address, status, date, expires) VALUES ('dep1', 'alice', 10, 25, 'TADDR', 'Pending', '2024-01-01', ?)", time.Now().Add(10*time.Minute).Unix()); err != nil {
		t.Fatalf("insert deposit: %v", err)
	}
	if _, err := db.Exec("DROP TABLE wallets"); err != nil {
		t.Fatalf("drop wallets: %v", err)
	}

	sess := createSession("admin", nil)
	body := url.Values{"id": {"dep1"}, "action": {"reject"}, "csrf_token": {"csrf-token"}}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/api/admin/deposit/action", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess})
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
	rr := httptest.NewRecorder()
	handleDepositAction(rr, req)
	if rr.Result().StatusCode != http.StatusFound {
		t.Fatalf("expected redirect, got %d", rr.Result().StatusCode)
	}

	var status string
	if err := db.QueryRow("SELECT status FROM deposits WHERE id='dep1'").Scan(&status); err != nil {
		t.Fatalf("query deposit: %v", err)
	}
	if status != "Pending" {
		t.Fatalf("expected pending status after rollback, got %q", status)
	}
}

func TestPanelL4SubmitSuccess(t *testing.T) {
	setupTestDB(t)
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('carol', 'x', 'Free', 'Active', 'tok', 'u#3', 0, 'ref', '', 0, 0)"); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := db.Exec("INSERT INTO plans (name, concurrents, max_time, vip, api) VALUES ('Free', 2, 60, 0, 0)"); err != nil {
		t.Fatalf("insert plan: %v", err)
	}
	if _, err := db.Exec("INSERT INTO methods (name, layer, command, enabled) VALUES ('UDP-FLOOD', 'layer4', 'UDP-FLOOD', 1)"); err != nil {
		t.Fatalf("insert method: %v", err)
	}

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	origHost := cfg.C2Host
	cfg.C2Host = server.URL
	t.Cleanup(func() { cfg.C2Host = origHost })

	sess := createSession("carol", nil)
	body := url.Values{
		"target":      {"1.1.1.1"},
		"port":        {"443"},
		"time":        {"10"},
		"concurrency": {"1"},
		"method":      {"UDP-FLOOD"},
		"csrf_token":  {"csrf-token"},
	}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/panel/l4/submit", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess})
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
	req.RemoteAddr = "127.0.0.1:1234"

	rr := httptest.NewRecorder()
	handlePanelL4Submit(rr, req)
	res := rr.Result()
	if res.StatusCode != http.StatusFound {
		t.Fatalf("expected redirect, got %d", res.StatusCode)
	}
	if loc := res.Header.Get("Location"); loc != "/panel?msg=attack_sent" {
		t.Fatalf("unexpected redirect location: %q", loc)
	}
}

func TestPanelL4RejectsLayer7Method(t *testing.T) {
	setupTestDB(t)
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('carol', 'x', 'Free', 'Active', 'tok', 'u#3', 0, 'ref', '', 0, 0)"); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := db.Exec("INSERT INTO methods (name, layer, command, enabled) VALUES ('HTTP-GET', 'layer7', 'HTTP-GET', 1)"); err != nil {
		t.Fatalf("insert method: %v", err)
	}

	sess := createSession("carol", nil)
	body := url.Values{
		"target":      {"1.1.1.1"},
		"port":        {"443"},
		"time":        {"10"},
		"concurrency": {"1"},
		"method":      {"HTTP-GET"},
		"csrf_token":  {"csrf-token"},
	}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/panel/l4/submit", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess})
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
	req.RemoteAddr = "127.0.0.1:1234"

	rr := httptest.NewRecorder()
	handlePanelL4Submit(rr, req)
	res := rr.Result()
	if res.StatusCode != http.StatusBadRequest {
		t.Fatalf("expected bad request, got %d", res.StatusCode)
	}
	if !strings.Contains(rr.Body.String(), "Selected method is not available") {
		t.Fatalf("expected method error in response")
	}
}

func TestLoadMethodsFromDBFiltersByLayer(t *testing.T) {
	setupTestDB(t)
	if _, err := db.Exec("INSERT INTO methods (name, layer, command, enabled) VALUES ('UDP-FLOOD', 'layer4', 'UDP-FLOOD', 1)"); err != nil {
		t.Fatalf("insert method: %v", err)
	}
	if _, err := db.Exec("INSERT INTO methods (name, layer, command, enabled) VALUES ('HTTP-GET', 'layer7', 'HTTP-GET', 1)"); err != nil {
		t.Fatalf("insert method: %v", err)
	}

	methodsMap, _ := loadMethodsFromDB()
	if len(methodsMap["layer4"]) != 1 || methodsMap["layer4"][0] != "UDP-FLOOD" {
		t.Fatalf("expected layer4 method, got %v", methodsMap["layer4"])
	}
	if len(methodsMap["layer7"]) != 1 || methodsMap["layer7"][0] != "HTTP-GET" {
		t.Fatalf("expected layer7 method, got %v", methodsMap["layer7"])
	}
}

func TestRegisterWithReferralStoresReferrer(t *testing.T) {
	setupTestDB(t)
	origCaptcha := captchaVerify
	captchaVerify = func(_, _ string) bool { return true }
	t.Cleanup(func() { captchaVerify = origCaptcha })

	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('referrer', 'x', 'Free', 'Active', 'tok', 'u#9', 0, 'REF1234', '', 0, 0)"); err != nil {
		t.Fatalf("insert referrer: %v", err)
	}

	body := url.Values{
		"username":   {"newuser"},
		"password":   {"pass1234"},
		"ref":        {"REF1234"},
		"captchaId":  {"id"},
		"captcha":    {"ok"},
		"csrf_token": {"csrf-token"},
	}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
	req.RemoteAddr = "127.0.0.1:1234"

	rr := httptest.NewRecorder()
	handleRegister(rr, req)
	if rr.Result().StatusCode != http.StatusFound {
		t.Fatalf("expected redirect, got %d", rr.Result().StatusCode)
	}

	var referredBy string
	var refPaid int
	if err := db.QueryRow("SELECT referred_by, ref_paid FROM users WHERE username='newuser'").Scan(&referredBy, &refPaid); err != nil {
		t.Fatalf("query new user: %v", err)
	}
	if referredBy != "referrer" {
		t.Fatalf("expected referred_by referrer, got %q", referredBy)
	}
	if refPaid != 0 {
		t.Fatalf("expected ref_paid 0, got %d", refPaid)
	}
}

func TestRegisterDefaultsToFreePlan(t *testing.T) {
	setupTestDB(t)
	origCaptcha := captchaVerify
	captchaVerify = func(_, _ string) bool { return true }
	t.Cleanup(func() { captchaVerify = origCaptcha })

	body := url.Values{
		"username":   {"newuser"},
		"password":   {"pass1234"},
		"captchaId":  {"id"},
		"captcha":    {"ok"},
		"csrf_token": {"csrf-token"},
	}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
	req.RemoteAddr = "127.0.0.1:1234"

	rr := httptest.NewRecorder()
	handleRegister(rr, req)
	if rr.Result().StatusCode != http.StatusFound {
		t.Fatalf("expected redirect, got %d", rr.Result().StatusCode)
	}

	var plan string
	if err := db.QueryRow("SELECT plan FROM users WHERE username='newuser'").Scan(&plan); err != nil {
		t.Fatalf("query new user plan: %v", err)
	}
	if plan != "Free" {
		t.Fatalf("expected Free plan, got %q", plan)
	}
}

func TestRegisterRejectsBadReferral(t *testing.T) {
	setupTestDB(t)
	origCaptcha := captchaVerify
	captchaVerify = func(_, _ string) bool { return true }
	t.Cleanup(func() { captchaVerify = origCaptcha })

	body := url.Values{
		"username":   {"newuser"},
		"password":   {"pass1234"},
		"ref":        {"NOPE"},
		"captchaId":  {"id"},
		"captcha":    {"ok"},
		"csrf_token": {"csrf-token"},
	}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/register", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
	req.RemoteAddr = "127.0.0.1:1234"

	rr := httptest.NewRecorder()
	handleRegister(rr, req)
	if rr.Result().StatusCode != http.StatusFound {
		t.Fatalf("expected redirect, got %d", rr.Result().StatusCode)
	}
	if loc := rr.Result().Header.Get("Location"); loc != "/register?err=bad_ref&ref=NOPE" {
		t.Fatalf("unexpected redirect: %q", loc)
	}
}

func TestCreateDepositIdempotent(t *testing.T) {
	setupTestDB(t)
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('alice', 'x', 'Free', 'Active', 'tok', 'u#1', 0, 'ref', '', 0, 0)"); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := db.Exec("INSERT INTO wallets (address, private_key, status, assigned_to) VALUES ('T123', 'key', 'Free', '')"); err != nil {
		t.Fatalf("insert wallet: %v", err)
	}
	cfg.BinanceAPI = "http://127.0.0.1:1"
	lastKnownTrxPrice = 0.2

	sess := createSession("alice", nil)
	body := url.Values{
		"csrf_token": {"csrf-token"},
		"amount":     {"25"},
		"request_id": {"req-1"},
	}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/api/deposit/create", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess})
	rr := httptest.NewRecorder()
	handleCreateDeposit(rr, req)

	if rr.Result().StatusCode != http.StatusFound {
		t.Fatalf("expected redirect, got %d", rr.Result().StatusCode)
	}
	loc := rr.Result().Header.Get("Location")
	if !strings.Contains(loc, "/deposit/pay?id=") {
		t.Fatalf("expected pay redirect, got %q", loc)
	}
	id := strings.TrimPrefix(strings.Split(loc, "&")[0], "/deposit/pay?id=")

	req2 := httptest.NewRequest(http.MethodPost, "/api/deposit/create", strings.NewReader(body))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
	req2.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess})
	rr2 := httptest.NewRecorder()
	handleCreateDeposit(rr2, req2)

	if rr2.Result().StatusCode != http.StatusFound {
		t.Fatalf("expected redirect, got %d", rr2.Result().StatusCode)
	}
	loc2 := rr2.Result().Header.Get("Location")
	if !strings.Contains(loc2, id) {
		t.Fatalf("expected same deposit id redirect, got %q", loc2)
	}

	var count int
	if err := db.QueryRow("SELECT count(*) FROM deposits WHERE user_id='alice'").Scan(&count); err != nil {
		t.Fatalf("count deposits: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 deposit, got %d", count)
	}
}

func TestCreateDepositUsesAvailableWallets(t *testing.T) {
	setupTestDB(t)
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('alice', 'x', 'Free', 'Active', 'tok', 'u#1', 0, 'ref', '', 0, 0)"); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := db.Exec("INSERT INTO wallets (address, private_key, status, assigned_to) VALUES ('T123', 'key', '', '')"); err != nil {
		t.Fatalf("insert wallet: %v", err)
	}
	cfg.BinanceAPI = "http://127.0.0.1:1"
	lastKnownTrxPrice = 0.2

	sess := createSession("alice", nil)
	body := url.Values{
		"csrf_token": {"csrf-token"},
		"amount":     {"25"},
	}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/api/deposit/create", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess})
	rr := httptest.NewRecorder()
	handleCreateDeposit(rr, req)

	if rr.Result().StatusCode != http.StatusFound {
		t.Fatalf("expected redirect, got %d", rr.Result().StatusCode)
	}
	if loc := rr.Result().Header.Get("Location"); !strings.Contains(loc, "/deposit/pay?id=") {
		t.Fatalf("expected pay redirect, got %q", loc)
	}
	var status string
	if err := db.QueryRow("SELECT status FROM wallets WHERE address='T123'").Scan(&status); err != nil {
		t.Fatalf("query wallet: %v", err)
	}
	if status != "Busy" {
		t.Fatalf("expected wallet to be busy, got %q", status)
	}
}

func TestCreateDepositFailsWhenWalletsUnavailable(t *testing.T) {
	setupTestDB(t)
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('alice', 'x', 'Free', 'Active', 'tok', 'u#1', 0, 'ref', '', 0, 0)"); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := db.Exec("INSERT INTO wallets (address, private_key, status, assigned_to) VALUES ('T123', 'key', 'Busy', 'dep1')"); err != nil {
		t.Fatalf("insert wallet: %v", err)
	}
	cfg.BinanceAPI = "http://127.0.0.1:1"
	lastKnownTrxPrice = 0.2

	sess := createSession("alice", nil)
	body := url.Values{
		"csrf_token": {"csrf-token"},
		"amount":     {"25"},
	}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/api/deposit/create", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess})
	rr := httptest.NewRecorder()
	handleCreateDeposit(rr, req)

	if rr.Result().StatusCode != http.StatusFound {
		t.Fatalf("expected redirect, got %d", rr.Result().StatusCode)
	}
	if loc := rr.Result().Header.Get("Location"); loc != "/deposit?err=wallets" {
		t.Fatalf("expected wallets error, got %q", loc)
	}
}

func TestPurchaseIdempotent(t *testing.T) {
	setupTestDB(t)
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('buyer', 'x', 'Free', 'Active', 'tok', 'u#2', 50, 'ref', '', 0, 0)"); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := db.Exec("INSERT INTO products (id, name, price, time, concurrents, vip, api_access) VALUES (1, 'Pro', 10, 60, 1, 0, 0)"); err != nil {
		t.Fatalf("insert product: %v", err)
	}

	sess := createSession("buyer", nil)
	body := url.Values{
		"csrf_token": {"csrf-token"},
		"request_id": {"purchase-1"},
	}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/api/market/purchase?id=1", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess})
	rr := httptest.NewRecorder()
	handlePurchase(rr, req)

	req2 := httptest.NewRequest(http.MethodPost, "/api/market/purchase?id=1", strings.NewReader(body))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
	req2.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess})
	rr2 := httptest.NewRecorder()
	handlePurchase(rr2, req2)

	if rr2.Result().StatusCode != http.StatusFound {
		t.Fatalf("expected redirect, got %d", rr2.Result().StatusCode)
	}
	if loc := rr2.Result().Header.Get("Location"); !strings.Contains(loc, "err=duplicate") {
		t.Fatalf("expected duplicate redirect, got %q", loc)
	}

	var balance float64
	if err := db.QueryRow("SELECT balance FROM users WHERE username='buyer'").Scan(&balance); err != nil {
		t.Fatalf("query balance: %v", err)
	}
	if balance != 40 {
		t.Fatalf("expected balance 40, got %.2f", balance)
	}
}

func TestCreateTicketRequestTooLarge(t *testing.T) {
	setupTestDB(t)
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('alice', 'x', 'Free', 'Active', 'tok', 'u#1', 0, 'ref', '', 0, 0)"); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	sess := createSession("alice", nil)

	largeMessage := strings.Repeat("a", maxBodySize*2)
	body := url.Values{
		"csrf_token": {"csrf-token"},
		"subject":    {"Help"},
		"category":   {"Billing"},
		"message":    {largeMessage},
	}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/api/ticket/create", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	if int64(len(body)) <= maxBodySize {
		req.ContentLength = maxBodySize + 1
	} else {
		req.ContentLength = int64(len(body))
	}
	if req.ContentLength <= maxBodySize {
		t.Fatalf("expected content length > max, got %d", req.ContentLength)
	}
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess})
	rr := httptest.NewRecorder()
	handleCreateTicket(rr, req)

	if rr.Result().StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("expected 413, got %d", rr.Result().StatusCode)
	}
}

func TestSupportEmptyStateRenders(t *testing.T) {
	setupTestDB(t)
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('alice', 'x', 'Free', 'Active', 'tok', 'u#1', 0, 'ref', '', 0, 0)"); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	sess := createSession("alice", nil)
	req := httptest.NewRequest(http.MethodGet, "/support", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess})
	rr := httptest.NewRecorder()
	handlePage("support.html")(rr, req)

	if rr.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected ok, got %d", rr.Result().StatusCode)
	}
	if !strings.Contains(rr.Body.String(), "No tickets yet.") {
		t.Fatalf("expected empty state message")
	}
}

func TestMarketRendersFreeAndCurrentPlan(t *testing.T) {
	setupTestDB(t)
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('alice', 'x', 'Pro', 'Active', 'tok', 'u#1', 0, 'ref', '', 0, 0)"); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := db.Exec("INSERT INTO products (id, name, price, time, concurrents, vip, api_access) VALUES (1, 'Pro', 10, 60, 1, 0, 0)"); err != nil {
		t.Fatalf("insert product: %v", err)
	}

	sess := createSession("alice", nil)
	req := httptest.NewRequest(http.MethodGet, "/market", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess})
	rr := httptest.NewRecorder()
	handlePage("market.html")(rr, req)

	if rr.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected ok, got %d", rr.Result().StatusCode)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "ALWAYS FREE") {
		t.Fatalf("expected Free plan card")
	}
	if !strings.Contains(body, "CURRENT PLAN") {
		t.Fatalf("expected current plan marker")
	}
}

func TestReferralCreditAppliesPerPurchaseAndIsIdempotent(t *testing.T) {
	setupTestDB(t)
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('referrer', 'x', 'Free', 'Active', 'tok', 'u#1', 0, 'REFCODE', '', 0, 0)"); err != nil {
		t.Fatalf("insert referrer: %v", err)
	}
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('buyer', 'x', 'Free', 'Active', 'tok', 'u#2', 50, 'BUYER', 'referrer', 0, 0)"); err != nil {
		t.Fatalf("insert buyer: %v", err)
	}
	if _, err := db.Exec("INSERT INTO products (id, name, price, time, concurrents, vip, api_access) VALUES (1, 'Pro', 10, 60, 1, 0, 0)"); err != nil {
		t.Fatalf("insert product: %v", err)
	}

	sess := createSession("buyer", nil)
	body := url.Values{"csrf_token": {"csrf-token"}, "request_id": {"req-1"}}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/api/market/purchase?id=1", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess})

	rr := httptest.NewRecorder()
	handlePurchase(rr, req)
	if rr.Result().StatusCode != http.StatusFound {
		t.Fatalf("expected redirect, got %d", rr.Result().StatusCode)
	}

	rr = httptest.NewRecorder()
	handlePurchase(rr, req)
	if rr.Result().StatusCode != http.StatusFound {
		t.Fatalf("expected redirect, got %d", rr.Result().StatusCode)
	}

	body = url.Values{"csrf_token": {"csrf-token"}, "request_id": {"req-2"}}.Encode()
	req = httptest.NewRequest(http.MethodPost, "/api/market/purchase?id=1", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess})
	rr = httptest.NewRecorder()
	handlePurchase(rr, req)
	if rr.Result().StatusCode != http.StatusFound {
		t.Fatalf("expected redirect, got %d", rr.Result().StatusCode)
	}

	var earnings float64
	if err := db.QueryRow("SELECT COALESCE(SUM(amount), 0) FROM referral_credits WHERE referrer='referrer'").Scan(&earnings); err != nil {
		t.Fatalf("query earnings: %v", err)
	}
	expected := roundFloat(2*10*cfg.ReferralPercent, 2)
	if earnings != expected {
		t.Fatalf("expected referral credit %v, got %v", expected, earnings)
	}
}

func TestReferralCreditSkipsSelfReferral(t *testing.T) {
	setupTestDB(t)
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('buyer', 'x', 'Free', 'Active', 'tok', 'u#2', 50, 'BUYER', 'buyer', 0, 0)"); err != nil {
		t.Fatalf("insert buyer: %v", err)
	}
	if _, err := db.Exec("INSERT INTO products (id, name, price, time, concurrents, vip, api_access) VALUES (1, 'Pro', 10, 60, 1, 0, 0)"); err != nil {
		t.Fatalf("insert product: %v", err)
	}

	sess := createSession("buyer", nil)
	body := url.Values{"csrf_token": {"csrf-token"}, "request_id": {"self-ref"}}.Encode()
	req := httptest.NewRequest(http.MethodPost, "/api/market/purchase?id=1", strings.NewReader(body))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess})

	rr := httptest.NewRecorder()
	handlePurchase(rr, req)
	if rr.Result().StatusCode != http.StatusFound {
		t.Fatalf("expected redirect, got %d", rr.Result().StatusCode)
	}

	var count int
	if err := db.QueryRow("SELECT count(*) FROM referral_credits").Scan(&count); err != nil {
		t.Fatalf("query referral credits: %v", err)
	}
	if count != 0 {
		t.Fatalf("expected no referral credits, got %d", count)
	}
}

func TestChangePasswordSuccessAndRevokesOtherSessions(t *testing.T) {
	setupTestDB(t)
	hash, err := generatePasswordHash("oldpass")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('alice', ?, 'Free', 'Active', 'tok', 'u#1', 0, 'ref', '', 0, 0)", hash); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	current := createSession("alice", nil)
	other := createSession("alice", nil)

	payload := map[string]string{"current": "oldpass", "next": "newpass123", "confirm": "newpass123"}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/user/change-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", "csrf-token")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: current})

	rr := httptest.NewRecorder()
	handleChangePassword(rr, req)
	if rr.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Result().StatusCode)
	}

	var count int
	if err := db.QueryRow("SELECT count(*) FROM sessions WHERE username='alice'").Scan(&count); err != nil {
		t.Fatalf("count sessions: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 session, got %d", count)
	}
	var remaining string
	if err := db.QueryRow("SELECT token FROM sessions WHERE username='alice'").Scan(&remaining); err != nil {
		t.Fatalf("fetch remaining session: %v", err)
	}
	if remaining != current {
		t.Fatalf("expected current session kept, got %q (other was %q)", remaining, other)
	}
}

func TestChangePasswordRejectsBadCurrent(t *testing.T) {
	setupTestDB(t)
	hash, err := generatePasswordHash("oldpass")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('alice', ?, 'Free', 'Active', 'tok', 'u#1', 0, 'ref', '', 0, 0)", hash); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	current := createSession("alice", nil)

	payload := map[string]string{"current": "wrong", "next": "newpass123", "confirm": "newpass123"}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/user/change-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", "csrf-token")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: current})

	rr := httptest.NewRecorder()
	handleChangePassword(rr, req)
	if rr.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Result().StatusCode)
	}
}

func TestChangePasswordRejectsMissingCSRF(t *testing.T) {
	setupTestDB(t)
	hash, err := generatePasswordHash("oldpass")
	if err != nil {
		t.Fatalf("hash password: %v", err)
	}
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('alice', ?, 'Free', 'Active', 'tok', 'u#1', 0, 'ref', '', 0, 0)", hash); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	current := createSession("alice", nil)

	payload := map[string]string{"current": "oldpass", "next": "newpass123", "confirm": "newpass123"}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/user/change-password", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: current})

	rr := httptest.NewRecorder()
	handleChangePassword(rr, req)
	if rr.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Result().StatusCode)
	}
}

func TestSessionsListAndRevoke(t *testing.T) {
	setupTestDB(t)
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('alice', 'x', 'Free', 'Active', 'tok', 'u#1', 0, 'ref', '', 0, 0)"); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	current := createSession("alice", nil)
	other := createSession("alice", nil)

	req := httptest.NewRequest(http.MethodGet, "/api/user/sessions", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: current})
	rr := httptest.NewRecorder()
	handleListSessions(rr, req)
	if rr.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Result().StatusCode)
	}
	var sessions []SessionInfo
	if err := json.NewDecoder(rr.Result().Body).Decode(&sessions); err != nil {
		t.Fatalf("decode sessions: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("expected 2 sessions, got %d", len(sessions))
	}
	var currentSeen bool
	for _, s := range sessions {
		if s.Token == current && s.IsCurrent {
			currentSeen = true
		}
	}
	if !currentSeen {
		t.Fatalf("expected current session marked")
	}

	payload := map[string]string{"token": other}
	body, _ := json.Marshal(payload)
	req = httptest.NewRequest(http.MethodPost, "/api/user/sessions/revoke", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-CSRF-Token", "csrf-token")
	req.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: current})
	rr = httptest.NewRecorder()
	handleRevokeSession(rr, req)
	if rr.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", rr.Result().StatusCode)
	}
}

func TestRevokeSessionRejectsMissingCSRF(t *testing.T) {
	setupTestDB(t)
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('alice', 'x', 'Free', 'Active', 'tok', 'u#1', 0, 'ref', '', 0, 0)"); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	current := createSession("alice", nil)

	payload := map[string]string{"token": current}
	body, _ := json.Marshal(payload)
	req := httptest.NewRequest(http.MethodPost, "/api/user/sessions/revoke", bytes.NewReader(body))
	req.Header.Set("Content-Type", "application/json")
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: current})
	rr := httptest.NewRecorder()
	handleRevokeSession(rr, req)
	if rr.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("expected 403, got %d", rr.Result().StatusCode)
	}
}
