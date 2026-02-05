package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"log"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestCreateDepositDeterministicWalletSelection(t *testing.T) {
	setupTestDB(t)
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('alice', 'x', 'Free', 'Active', 'tok', 'u#1', 0, 'ref', '', 0, 0)"); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	if _, err := db.Exec("INSERT INTO wallets (address, private_key, status, assigned_to) VALUES ('T111', 'key', 'Free', '')"); err != nil {
		t.Fatalf("insert wallet 1: %v", err)
	}
	if _, err := db.Exec("INSERT INTO wallets (address, private_key, status, assigned_to) VALUES ('T222', 'key', 'Free', '')"); err != nil {
		t.Fatalf("insert wallet 2: %v", err)
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

	loc := rr.Result().Header.Get("Location")
	if !strings.Contains(loc, "/deposit/pay?id=") {
		t.Fatalf("expected pay redirect, got %q", loc)
	}
	dep1 := strings.TrimPrefix(strings.Split(loc, "&")[0], "/deposit/pay?id=")

	rr2 := httptest.NewRecorder()
	req2 := httptest.NewRequest(http.MethodPost, "/api/deposit/create", strings.NewReader(body))
	req2.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req2.AddCookie(&http.Cookie{Name: csrfCookieName, Value: "csrf-token"})
	req2.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess})
	handleCreateDeposit(rr2, req2)

	loc2 := rr2.Result().Header.Get("Location")
	if !strings.Contains(loc2, "/deposit/pay?id=") {
		t.Fatalf("expected pay redirect, got %q", loc2)
	}
	dep2 := strings.TrimPrefix(strings.Split(loc2, "&")[0], "/deposit/pay?id=")

	var addr1, addr2 string
	if err := db.QueryRow("SELECT address FROM deposits WHERE id=?", dep1).Scan(&addr1); err != nil {
		t.Fatalf("query deposit 1: %v", err)
	}
	if err := db.QueryRow("SELECT address FROM deposits WHERE id=?", dep2).Scan(&addr2); err != nil {
		t.Fatalf("query deposit 2: %v", err)
	}
	if addr1 != "T111" || addr2 != "T222" {
		t.Fatalf("expected deterministic wallet order, got %q and %q", addr1, addr2)
	}
}

func TestNormalizeWalletsHandlesEmptyStatus(t *testing.T) {
	setupTestDB(t)
	if _, err := db.Exec("INSERT INTO wallets (address, private_key, status, assigned_to) VALUES ('TEMPTY', 'key', NULL, '  ')"); err != nil {
		t.Fatalf("insert wallet: %v", err)
	}
	if err := normalizeWallets(time.Now()); err != nil {
		t.Fatalf("normalize wallets: %v", err)
	}
	var status sql.NullString
	var assigned sql.NullString
	if err := db.QueryRow("SELECT status, assigned_to FROM wallets WHERE address='TEMPTY'").Scan(&status, &assigned); err != nil {
		t.Fatalf("query wallet: %v", err)
	}
	if status.String != "Free" {
		t.Fatalf("expected status Free, got %q", status.String)
	}
	if assigned.Valid {
		t.Fatalf("expected assigned_to NULL, got %v", assigned.String)
	}
}

func TestExpiredDepositsReleaseWallet(t *testing.T) {
	setupTestDB(t)
	if _, err := db.Exec("INSERT INTO wallets (address, private_key, status, assigned_to) VALUES ('TEXP', 'key', 'Busy', 'dep-exp')"); err != nil {
		t.Fatalf("insert wallet: %v", err)
	}
	if _, err := db.Exec("INSERT INTO deposits (id, user_id, amount, address, status, date, expires) VALUES ('dep-exp', 'alice', 1, 'TEXP', 'Pending', '2024-01-01 00:00', ?)", time.Now().Add(-1*time.Hour).Unix()); err != nil {
		t.Fatalf("insert deposit: %v", err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	now := time.Now()
	if err := expirePendingDepositsTx(tx, now); err != nil {
		_ = tx.Rollback()
		t.Fatalf("expire pending deposits: %v", err)
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("commit: %v", err)
	}
	var status string
	var assigned sql.NullString
	if err := db.QueryRow("SELECT status, assigned_to FROM wallets WHERE address='TEXP'").Scan(&status, &assigned); err != nil {
		t.Fatalf("query wallet: %v", err)
	}
	if status != "Free" || assigned.Valid {
		t.Fatalf("expected wallet freed, got status=%q assigned=%v", status, assigned)
	}
	var depStatus string
	if err := db.QueryRow("SELECT status FROM deposits WHERE id='dep-exp'").Scan(&depStatus); err != nil {
		t.Fatalf("query deposit: %v", err)
	}
	if depStatus != "Expired" {
		t.Fatalf("expected deposit expired, got %q", depStatus)
	}
}

func TestConcurrentReservationsUseDistinctWallets(t *testing.T) {
	setupTestDB(t)
	if _, err := db.Exec("INSERT INTO wallets (address, private_key, status, assigned_to) VALUES ('T1', 'key', 'Free', '')"); err != nil {
		t.Fatalf("insert wallet 1: %v", err)
	}
	if _, err := db.Exec("INSERT INTO wallets (address, private_key, status, assigned_to) VALUES ('T2', 'key', 'Free', '')"); err != nil {
		t.Fatalf("insert wallet 2: %v", err)
	}

	now := time.Now()
	type result struct {
		id  int64
		err error
	}
	results := make(chan result, 2)
	var wg sync.WaitGroup
	wg.Add(2)
	for _, depID := range []string{"dep1", "dep2"} {
		depID := depID
		go func() {
			defer wg.Done()
			tx, err := db.Begin()
			if err != nil {
				results <- result{err: err}
				return
			}
			row, err := reserveUsableWalletTx(tx, now, depID)
			if err != nil {
				_ = tx.Rollback()
				results <- result{err: err}
				return
			}
			if _, err := tx.Exec("INSERT INTO deposits (id, user_id, amount, address, status, date, expires) VALUES (?, ?, ?, ?, 'Pending', '2024-01-01 00:00', ?)", depID, "alice", 1, row.Address, now.Add(10*time.Minute).Unix()); err != nil {
				_ = tx.Rollback()
				results <- result{err: err}
				return
			}
			if err := tx.Commit(); err != nil {
				results <- result{err: err}
				return
			}
			results <- result{id: row.RowID}
		}()
	}
	wg.Wait()
	close(results)
	ids := make(map[int64]struct{})
	for res := range results {
		if res.err != nil {
			t.Fatalf("reservation error: %v", res.err)
		}
		ids[res.id] = struct{}{}
	}
	if len(ids) != 2 {
		t.Fatalf("expected distinct wallets, got %v", ids)
	}
}

func TestRollbackRestoresWalletState(t *testing.T) {
	setupTestDB(t)
	if _, err := db.Exec("INSERT INTO wallets (address, private_key, status, assigned_to) VALUES ('TROLL', 'key', 'Free', NULL)"); err != nil {
		t.Fatalf("insert wallet: %v", err)
	}
	tx, err := db.Begin()
	if err != nil {
		t.Fatalf("begin tx: %v", err)
	}
	if _, err := reserveUsableWalletTx(tx, time.Now(), "dep-rollback"); err != nil {
		_ = tx.Rollback()
		t.Fatalf("reserve wallet: %v", err)
	}
	if err := tx.Rollback(); err != nil {
		t.Fatalf("rollback: %v", err)
	}
	var status string
	var assigned sql.NullString
	if err := db.QueryRow("SELECT status, assigned_to FROM wallets WHERE address='TROLL'").Scan(&status, &assigned); err != nil {
		t.Fatalf("query wallet: %v", err)
	}
	if status != "Free" || assigned.Valid {
		t.Fatalf("expected wallet restored, got status=%q assigned=%v", status, assigned)
	}
}

func TestNoWalletsLogsDiagnostics(t *testing.T) {
	setupTestDB(t)
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('alice', 'x', 'Free', 'Active', 'tok', 'u#1', 0, 'ref', '', 0, 0)"); err != nil {
		t.Fatalf("insert user: %v", err)
	}
	cfg.BinanceAPI = "http://127.0.0.1:1"
	lastKnownTrxPrice = 0.2

	var buf bytes.Buffer
	origOutput := log.Writer()
	origFlags := log.Flags()
	log.SetOutput(&buf)
	log.SetFlags(0)
	t.Cleanup(func() {
		log.SetOutput(origOutput)
		log.SetFlags(origFlags)
	})

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

	if loc := rr.Result().Header.Get("Location"); loc != "/deposit?err=wallets" {
		t.Fatalf("expected wallets error, got %q", loc)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	var entry depositErrorLog
	found := false
	for _, line := range lines {
		if strings.Contains(line, "\"event\":\"deposit_error\"") {
			if err := json.Unmarshal([]byte(line), &entry); err != nil {
				t.Fatalf("unmarshal log: %v", err)
			}
			found = true
			break
		}
	}
	if !found {
		t.Fatalf("expected deposit_error log, got %q", buf.String())
	}
	if entry.Category != "NO_USABLE_WALLETS" {
		t.Fatalf("expected NO_USABLE_WALLETS category, got %q", entry.Category)
	}
	if entry.Diagnostics == nil || entry.Diagnostics.TotalWallets != 0 {
		t.Fatalf("expected diagnostics with zero wallets, got %+v", entry.Diagnostics)
	}
	if strings.Contains(buf.String(), "\"address\":\"") {
		t.Fatalf("log should not include wallet addresses: %s", buf.String())
	}
}
