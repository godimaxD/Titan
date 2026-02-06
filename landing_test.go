package main

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLandingShowsProducts(t *testing.T) {
	setupTestDB(t)
	if _, err := db.Exec("INSERT INTO products (name, price, time, concurrents, vip, api_access) VALUES (?, ?, ?, ?, ?, ?)", "Starter Alpha", 99, 120, 3, false, false); err != nil {
		t.Fatalf("insert product 1: %v", err)
	}
	if _, err := db.Exec("INSERT INTO products (name, price, time, concurrents, vip, api_access) VALUES (?, ?, ?, ?, ?, ?)", "Galaxy Beta", 199, 240, 5, true, true); err != nil {
		t.Fatalf("insert product 2: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handleLanding(rr, req)

	body := rr.Body.String()
	if !strings.Contains(body, "Starter Alpha") || !strings.Contains(body, "Galaxy Beta") {
		t.Fatalf("expected landing page to include product names")
	}
	if !strings.Contains(body, fmt.Sprintf("%v $", 99)) || !strings.Contains(body, fmt.Sprintf("%v $", 199)) {
		t.Fatalf("expected landing page to include product prices")
	}
}

func TestLandingShowsAtMostSixProducts(t *testing.T) {
	setupTestDB(t)
	for i := 1; i <= 7; i++ {
		name := fmt.Sprintf("Product %d", i)
		if _, err := db.Exec("INSERT INTO products (name, price, time, concurrents, vip, api_access) VALUES (?, ?, ?, ?, ?, ?)", name, float64(10*i), 60*i, i, false, false); err != nil {
			t.Fatalf("insert product %d: %v", i, err)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handleLanding(rr, req)

	body := rr.Body.String()
	if strings.Contains(body, "Product 1") {
		t.Fatalf("expected oldest product to be omitted from landing page")
	}
	for i := 2; i <= 7; i++ {
		name := fmt.Sprintf("Product %d", i)
		if !strings.Contains(body, name) {
			t.Fatalf("expected landing page to include %s", name)
		}
	}
	if count := strings.Count(body, "relative border rounded-2xl p-8 flex flex-col transition-all"); count != 6 {
		t.Fatalf("expected 6 product cards, got %d", count)
	}
}

func TestLandingKeepsCardMarkupClass(t *testing.T) {
	setupTestDB(t)
	if _, err := db.Exec("INSERT INTO products (name, price, time, concurrents, vip, api_access) VALUES (?, ?, ?, ?, ?, ?)", "Starter Beta", 49, 30, 1, false, false); err != nil {
		t.Fatalf("insert product: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	rr := httptest.NewRecorder()
	handleLanding(rr, req)

	body := rr.Body.String()
	requiredClasses := []string{
		"relative border rounded-2xl p-8 flex flex-col transition-all",
		"bg-card",
		"border-border",
		"text-muted-foreground",
		"text-foreground/80 mb-4",
	}
	for _, class := range requiredClasses {
		if !strings.Contains(body, class) {
			t.Fatalf("expected landing page to include class %q", class)
		}
	}
	requiredLabels := []string{"Per Month", "Features"}
	for _, label := range requiredLabels {
		if !strings.Contains(body, label) {
			t.Fatalf("expected landing page to include label %q", label)
		}
	}
}
