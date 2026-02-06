package main

import (
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"
)

func renderDashboard(t *testing.T, now time.Time) string {
	t.Helper()
	setupTestDB(t)

	users := []string{"alice", "bob", "carol"}
	for i, user := range users {
		if _, err := db.Exec(
			"INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES (?, 'x', 'Free', 'Active', ?, ?, 0, 'ref', '', 0, 0)",
			user,
			"tok-"+user,
			"u#"+string(rune('1'+i)),
		); err != nil {
			t.Fatalf("insert user: %v", err)
		}
	}

	attacks := []struct {
		id      string
		status  string
		endTime int64
	}{
		{"a1", "running", now.Add(-2 * time.Minute).Unix()},
		{"a2", "stopped", now.Add(5 * time.Minute).Unix()},
		{"a3", "running", now.Add(30 * time.Second).Unix()},
		{"a4", "stopped", now.Add(-10 * time.Second).Unix()},
	}
	for _, attack := range attacks {
		if _, err := db.Exec("INSERT INTO attacks (id, status, end_time) VALUES (?, ?, ?)", attack.id, attack.status, attack.endTime); err != nil {
			t.Fatalf("insert attack: %v", err)
		}
	}

	sess := createSession("alice", nil)
	if sess == "" {
		t.Fatalf("expected session token")
	}

	req := httptest.NewRequest(http.MethodGet, "/dashboard", nil)
	req.AddCookie(&http.Cookie{Name: sessionCookieName, Value: sess})

	rr := httptest.NewRecorder()
	handlePage("dashboard.html")(rr, req)

	if rr.Result().StatusCode != http.StatusOK {
		t.Fatalf("expected status 200, got %d", rr.Result().StatusCode)
	}

	return rr.Body.String()
}

func TestDashboardRendersUserCount(t *testing.T) {
	now := time.Now()
	body := renderDashboard(t, now)

	pattern := regexp.MustCompile(`(?s)Total Users</span>.*?text-3xl font-black text-white mb-4">3</div>`)
	if !pattern.MatchString(body) {
		t.Fatalf("expected total users count to render, body: %s", body)
	}
}

func TestDashboardRendersTotalAttackCount(t *testing.T) {
	now := time.Now()
	body := renderDashboard(t, now)

	pattern := regexp.MustCompile(`(?s)Total Attacks</span>.*?text-3xl font-black text-white mb-4">4</div>`)
	if !pattern.MatchString(body) {
		t.Fatalf("expected total attacks count to render, body: %s", body)
	}
}

func TestDashboardRendersRunningAttackCount(t *testing.T) {
	now := time.Now()
	body := renderDashboard(t, now)

	pattern := regexp.MustCompile(`(?s)Running Attacks</span>.*?text-3xl font-black text-white mb-4">3</div>`)
	if !pattern.MatchString(body) {
		t.Fatalf("expected running attacks count to render, body: %s", body)
	}
}

func TestDashboardMarkupPreserved(t *testing.T) {
	now := time.Now()
	body := renderDashboard(t, now)

	checks := []string{
		"glass-panel p-6 rounded-2xl border border-white/5 ",
		"Total Users",
		"Active Operators",
		"Total Attacks",
		"Packets Sent",
		"Running Attacks",
		"Network Load",
		`bg-green-500/10 text-green-400 text-xs px-2 py-1 rounded border border-green-500/20 animate-pulse">LIVE</span>`,
	}
	for _, check := range checks {
		if !strings.Contains(body, check) {
			t.Fatalf("expected dashboard markup to contain %q", check)
		}
	}
}
