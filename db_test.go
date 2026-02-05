package main

import "testing"

func TestRotateDefaultAdminAPIToken(t *testing.T) {
	setupTestDB(t)
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES ('admin', 'x', 'God', 'Active', ?, 'u#0', 0, 'ref', '', 0, 0)", defaultAdminAPIToken); err != nil {
		t.Fatalf("insert admin: %v", err)
	}
	t.Setenv("TITAN_ADMIN_API_TOKEN", "new-admin-token")

	rotateDefaultAdminAPIToken()

	var token string
	if err := db.QueryRow("SELECT api_token FROM users WHERE username='admin'").Scan(&token); err != nil {
		t.Fatalf("query admin token: %v", err)
	}
	if token != "new-admin-token" {
		t.Fatalf("expected token rotation to use env token, got %q", token)
	}
}
