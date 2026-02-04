package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func setupTestDB(t *testing.T) {
	t.Helper()
	var err error
	db, err = sql.Open("sqlite3", ":memory:")
	if err != nil {
		t.Fatalf("open db: %v", err)
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
		`CREATE TABLE wallets (address TEXT PRIMARY KEY, private_key TEXT, status TEXT, assigned_to TEXT);`,
		`CREATE TABLE methods (name TEXT PRIMARY KEY, layer TEXT, command TEXT, enabled BOOLEAN DEFAULT 1, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);`,
		`CREATE TABLE blacklist (target TEXT PRIMARY KEY, reason TEXT, date TEXT);`,
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
	if loc := rr.Result().Header.Get("Location"); loc != "/dashboard?msg=success" {
		t.Fatalf("unexpected redirect location: %q", loc)
	}
}

func TestHandleAddWalletAdmin(t *testing.T) {
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
	if loc := rr.Result().Header.Get("Location"); loc != "/register?err=bad_ref" {
		t.Fatalf("unexpected redirect: %q", loc)
	}
}

func TestReferralCreditAppliedOnce(t *testing.T) {
	setupTestDB(t)
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('referrer', 'x', 'Free', 'Active', 'tok', 'u#1', 0, 'REFCODE', '', 0, 0)"); err != nil {
		t.Fatalf("insert referrer: %v", err)
	}
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('buyer', 'x', 'Free', 'Active', 'tok', 'u#2', 30, 'BUYER', 'referrer', 0, 0)"); err != nil {
		t.Fatalf("insert buyer: %v", err)
	}
	if _, err := db.Exec("INSERT INTO products (id, name, price, time, concurrents, vip, api_access) VALUES (1, 'Pro', 10, 60, 1, 0, 0)"); err != nil {
		t.Fatalf("insert product: %v", err)
	}

	sess := createSession("buyer", nil)
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

	rr = httptest.NewRecorder()
	handlePurchase(rr, req)
	if rr.Result().StatusCode != http.StatusFound {
		t.Fatalf("expected redirect, got %d", rr.Result().StatusCode)
	}

	var earnings float64
	if err := db.QueryRow("SELECT ref_earnings FROM users WHERE username='referrer'").Scan(&earnings); err != nil {
		t.Fatalf("query earnings: %v", err)
	}
	if earnings != roundFloat(10*cfg.ReferralPercent, 2) {
		t.Fatalf("expected single referral credit, got %v", earnings)
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
