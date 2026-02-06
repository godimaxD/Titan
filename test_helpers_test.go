package main

import "testing"

func sessionCSRFToken(t *testing.T, sessionToken string) string {
	t.Helper()
	var csrf string
	if err := db.QueryRow("SELECT csrf_token FROM sessions WHERE token=?", sessionToken).Scan(&csrf); err != nil {
		t.Fatalf("query csrf token: %v", err)
	}
	if csrf == "" {
		t.Fatalf("expected csrf token for session %q", sessionToken)
	}
	return csrf
}
