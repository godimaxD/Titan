package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func setupActivityLogger(t *testing.T) {
	t.Helper()
	activityLogDir = t.TempDir()
	if err := initActivityLogger(); err != nil {
		t.Fatalf("init activity logger: %v", err)
	}
}

func TestLogActivityWritesToFileAndDB(t *testing.T) {
	setupTestDB(t)
	setupActivityLogger(t)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	LogActivity(req, ActivityLogEntry{
		ActorType: actorTypeSystem,
		Action:    "SYSTEM_TEST_EVENT",
		Severity:  severityInfo,
		Message:   "Log write test.",
	})

	logPath := filepath.Join(activityLogDir, "activity.log")
	data, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("read log file: %v", err)
	}
	if !strings.Contains(string(data), "SYSTEM_TEST_EVENT") {
		t.Fatalf("expected log entry in file")
	}

	var count int
	if err := db.QueryRow("SELECT count(*) FROM activity_logs").Scan(&count); err != nil {
		t.Fatalf("query activity logs: %v", err)
	}
	if count != 1 {
		t.Fatalf("expected 1 activity log, got %d", count)
	}
}

func TestActivitySearchRequiresAdmin(t *testing.T) {
	setupTestDB(t)
	setupActivityLogger(t)

	req := httptest.NewRequest(http.MethodGet, "/api/admin/activity/search", nil)
	rr := httptest.NewRecorder()
	handleActivitySearch(rr, req)

	if rr.Result().StatusCode != http.StatusForbidden {
		t.Fatalf("expected forbidden status, got %d", rr.Result().StatusCode)
	}
}

func TestActivitySearchFilters(t *testing.T) {
	setupTestDB(t)
	setupActivityLogger(t)

	_, _ = db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('admin', 'x', 'God', 'Active', 'tok', 'u#0', 0, 'ref', '', 0, 0)")
	sess := createSession("admin", nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	LogActivity(req, ActivityLogEntry{
		ActorType: actorTypeUser,
		Action:    "AUTH_LOGIN_SUCCESS",
		Severity:  severityInfo,
		Username:  "alice",
		Message:   "Login ok.",
	})
	LogActivity(req, ActivityLogEntry{
		ActorType: actorTypeUser,
		Action:    "AUTH_LOGIN_FAILED",
		Severity:  severityWarn,
		Username:  "bob",
		Message:   "Login failed.",
	})

	searchReq := httptest.NewRequest(http.MethodGet, "/api/admin/activity/search?action=AUTH_LOGIN_SUCCESS", nil)
	searchReq.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess})
	rr := httptest.NewRecorder()
	handleActivitySearch(rr, searchReq)

	if rr.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected ok status, got %d", rr.Result().StatusCode)
	}
	var payload struct {
		Items []ActivityLogRecord `json:"items"`
		Total int                 `json:"total"`
	}
	if err := json.NewDecoder(rr.Body).Decode(&payload); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	if payload.Total != 1 || len(payload.Items) != 1 {
		t.Fatalf("expected 1 record, got total=%d len=%d", payload.Total, len(payload.Items))
	}
	if payload.Items[0].Action != "AUTH_LOGIN_SUCCESS" {
		t.Fatalf("unexpected action: %s", payload.Items[0].Action)
	}
}

func TestActivityExportRespectsFilters(t *testing.T) {
	setupTestDB(t)
	setupActivityLogger(t)

	_, _ = db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('admin', 'x', 'God', 'Active', 'tok', 'u#0', 0, 'ref', '', 0, 0)")
	sess := createSession("admin", nil)

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	LogActivity(req, ActivityLogEntry{
		ActorType: actorTypeUser,
		Action:    "AUTH_LOGIN_SUCCESS",
		Severity:  severityInfo,
		Username:  "alice",
		Message:   "Login ok.",
	})
	LogActivity(req, ActivityLogEntry{
		ActorType: actorTypeUser,
		Action:    "AUTH_LOGIN_FAILED",
		Severity:  severityWarn,
		Username:  "bob",
		Message:   "Login failed.",
	})

	exportReq := httptest.NewRequest(http.MethodGet, "/api/admin/activity/export?format=jsonl&severity=INFO", nil)
	exportReq.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess})
	rr := httptest.NewRecorder()
	handleActivityExport(rr, exportReq)

	if rr.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected ok status, got %d", rr.Result().StatusCode)
	}
	body := rr.Body.String()
	if !strings.Contains(body, "AUTH_LOGIN_SUCCESS") || strings.Contains(body, "AUTH_LOGIN_FAILED") {
		t.Fatalf("export did not respect filters: %s", body)
	}
}
