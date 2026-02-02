package main

import (
	"database/sql"
	"log"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "./titan.db")
	if err != nil {
		log.Fatal(err)
	}

	tables := []string{
	`CREATE TABLE IF NOT EXISTS users (
	username TEXT PRIMARY KEY, password TEXT, plan TEXT, status TEXT, api_token TEXT, user_id TEXT, balance REAL DEFAULT 0,
	ref_code TEXT, referred_by TEXT, ref_earnings REAL DEFAULT 0
	);`,
	`CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, username TEXT, expires INTEGER, created_at INTEGER, last_seen INTEGER, user_agent TEXT, ip TEXT);`,
	`CREATE TABLE IF NOT EXISTS tickets (id TEXT PRIMARY KEY, user_id TEXT, category TEXT, subject TEXT, status TEXT, last_update DATETIME, messages TEXT);`,
	`CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, price REAL, time INTEGER, concurrents INTEGER, vip BOOLEAN, api_access BOOLEAN);`,
	`CREATE TABLE IF NOT EXISTS plans (name TEXT PRIMARY KEY, concurrents INTEGER, max_time INTEGER, vip BOOLEAN, api BOOLEAN);`,
	`CREATE TABLE IF NOT EXISTS redeem_codes (code TEXT PRIMARY KEY, plan TEXT, used BOOLEAN);`,
	`CREATE TABLE IF NOT EXISTS deposits (id TEXT PRIMARY KEY, user_id TEXT, amount REAL, address TEXT, status TEXT, date TEXT, expires INTEGER, usd_amount REAL DEFAULT 0);`,
	`CREATE TABLE IF NOT EXISTS wallets (address TEXT PRIMARY KEY, private_key TEXT, status TEXT, assigned_to TEXT);`,
	`CREATE TABLE IF NOT EXISTS blacklist (target TEXT PRIMARY KEY, reason TEXT, date TEXT);`,
	`CREATE TABLE IF NOT EXISTS methods (name TEXT PRIMARY KEY, layer TEXT, command TEXT, enabled BOOLEAN DEFAULT 1, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);`,
	}
	for _, t := range tables {
		if _, err := db.Exec(t); err != nil {
			log.Printf("DB Init Error (Table): %v", err)
		}
	}

	// Migrations (ignore errors if columns exist)
	db.Exec("ALTER TABLE deposits ADD COLUMN usd_amount REAL DEFAULT 0;")
	db.Exec("ALTER TABLE users ADD COLUMN ref_code TEXT;")
	db.Exec("ALTER TABLE users ADD COLUMN referred_by TEXT;")
	db.Exec("ALTER TABLE users ADD COLUMN ref_earnings REAL DEFAULT 0;")
	// Session metadata
	db.Exec("ALTER TABLE sessions ADD COLUMN created_at INTEGER;")
	db.Exec("ALTER TABLE sessions ADD COLUMN last_seen INTEGER;")
	db.Exec("ALTER TABLE sessions ADD COLUMN user_agent TEXT;")
	db.Exec("ALTER TABLE sessions ADD COLUMN ip TEXT;")
	db.Exec("UPDATE deposits SET usd_amount = amount * 0.20 WHERE (usd_amount IS NULL OR usd_amount = 0) AND amount > 0")

	// Seed default methods if table is empty
	var mCount int
	if err := db.QueryRow("SELECT count(*) FROM methods").Scan(&mCount); err == nil && mCount == 0 {
		defaults := []struct{ name, layer, command string }{
			{"UDP-FLOOD", "layer4", "UDP-FLOOD"},
			{"TCP-SYN", "layer4", "TCP-SYN"},
			{"OVH-GAME", "layer4", "OVH-GAME"},
			{"DNS-AMP", "layer4", "DNS-AMP"},
			{"ACK-FLOOD", "layer4", "ACK-FLOOD"},
			{"HTTP-GET", "layer7", "HTTP-GET"},
			{"HTTP-POST", "layer7", "HTTP-POST"},
			{"CF-UAM", "layer7", "CF-UAM"},
			{"TLS-V2", "layer7", "TLS-V2"},
		}
		for _, d := range defaults {
			_, _ = db.Exec("INSERT OR IGNORE INTO methods(name, layer, command, enabled) VALUES (?, ?, ?, 1)", d.name, d.layer, d.command)
		}
	}

	var adminPass string
	err = db.QueryRow("SELECT password FROM users WHERE username='admin'").Scan(&adminPass)
	if err == sql.ErrNoRows {
		hashedPass, err := generatePasswordHash("admin")
		if err != nil {
			log.Fatal("Failed to hash admin password:", err)
		}
		_, err = db.Exec("INSERT INTO users VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", "admin", hashedPass, "God", "Active", "titan_root", "user#0001", 999.0, "ADMIN", "", 0.0)
		if err != nil {
			log.Fatal("Failed to insert admin user:", err)
		}
	}
}
