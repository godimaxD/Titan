package main

import (
	"database/sql"
	"log"
	"os"
	"strings"
	"time"

	_ "github.com/mattn/go-sqlite3"
)

var db *sql.DB

const defaultAdminAPIToken = "titan_root"

func initDB() {
	var err error
	db, err = sql.Open("sqlite3", "./titan.db")
	if err != nil {
		log.Fatal(err)
	}

	tables := []string{
		`CREATE TABLE IF NOT EXISTS users (
	username TEXT PRIMARY KEY, password TEXT, plan TEXT, status TEXT, api_token TEXT, user_id TEXT, balance REAL DEFAULT 0,
	ref_code TEXT, referred_by TEXT, ref_earnings REAL DEFAULT 0, ref_paid INTEGER DEFAULT 0
	);`,
		`CREATE TABLE IF NOT EXISTS sessions (token TEXT PRIMARY KEY, username TEXT, expires INTEGER, created_at INTEGER, last_seen INTEGER, user_agent TEXT, ip TEXT);`,
		`CREATE TABLE IF NOT EXISTS tickets (id TEXT PRIMARY KEY, user_id TEXT, category TEXT, subject TEXT, status TEXT, last_update DATETIME, messages TEXT);`,
		`CREATE TABLE IF NOT EXISTS products (id INTEGER PRIMARY KEY AUTOINCREMENT, name TEXT, price REAL, time INTEGER, concurrents INTEGER, vip BOOLEAN, api_access BOOLEAN);`,
		`CREATE TABLE IF NOT EXISTS plans (name TEXT PRIMARY KEY, concurrents INTEGER, max_time INTEGER, vip BOOLEAN, api BOOLEAN);`,
		`CREATE TABLE IF NOT EXISTS redeem_codes (code TEXT PRIMARY KEY, plan TEXT, used BOOLEAN);`,
		`CREATE TABLE IF NOT EXISTS deposits (id TEXT PRIMARY KEY, user_id TEXT, amount REAL, address TEXT, status TEXT, date TEXT, expires INTEGER, usd_amount REAL DEFAULT 0, confirmed_at TEXT, txid TEXT, fee REAL DEFAULT 0, notes TEXT);`,
		`CREATE TABLE IF NOT EXISTS wallets (address TEXT PRIMARY KEY, private_key TEXT, status TEXT, assigned_to TEXT);`,
		`CREATE TABLE IF NOT EXISTS blacklist (target TEXT PRIMARY KEY, reason TEXT, date TEXT);`,
		`CREATE TABLE IF NOT EXISTS methods (name TEXT PRIMARY KEY, layer TEXT, command TEXT, enabled BOOLEAN DEFAULT 1, created_at DATETIME DEFAULT CURRENT_TIMESTAMP);`,
		`CREATE TABLE IF NOT EXISTS idempotency_keys (key TEXT PRIMARY KEY, user_id TEXT, action TEXT, reference_id TEXT, created_at INTEGER);`,
		`CREATE TABLE IF NOT EXISTS referral_credits (
			purchase_key TEXT PRIMARY KEY,
			buyer TEXT,
			referrer TEXT,
			amount REAL,
			product_id INTEGER,
			created_at TEXT
		);`,
		`CREATE TABLE IF NOT EXISTS activity_logs (
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
	for _, t := range tables {
		if _, err := db.Exec(t); err != nil {
			log.Printf("DB Init Error (Table): %v", err)
		}
	}

	// Migrations (ignore errors if columns exist)
	db.Exec("ALTER TABLE deposits ADD COLUMN usd_amount REAL DEFAULT 0;")
	db.Exec("ALTER TABLE deposits ADD COLUMN confirmed_at TEXT;")
	db.Exec("ALTER TABLE deposits ADD COLUMN txid TEXT;")
	db.Exec("ALTER TABLE deposits ADD COLUMN fee REAL DEFAULT 0;")
	db.Exec("ALTER TABLE deposits ADD COLUMN notes TEXT;")
	db.Exec("ALTER TABLE users ADD COLUMN ref_code TEXT;")
	db.Exec("ALTER TABLE users ADD COLUMN referred_by TEXT;")
	db.Exec("ALTER TABLE users ADD COLUMN ref_earnings REAL DEFAULT 0;")
	db.Exec("ALTER TABLE users ADD COLUMN ref_paid INTEGER DEFAULT 0;")
	db.Exec("ALTER TABLE methods ADD COLUMN layer TEXT;")
	db.Exec("ALTER TABLE wallets ADD COLUMN status TEXT;")
	db.Exec("ALTER TABLE wallets ADD COLUMN assigned_to TEXT;")
	// Session metadata
	db.Exec("ALTER TABLE sessions ADD COLUMN created_at INTEGER;")
	db.Exec("ALTER TABLE sessions ADD COLUMN last_seen INTEGER;")
	db.Exec("ALTER TABLE sessions ADD COLUMN user_agent TEXT;")
	db.Exec("ALTER TABLE sessions ADD COLUMN ip TEXT;")
	db.Exec("UPDATE deposits SET usd_amount = amount * 0.20 WHERE (usd_amount IS NULL OR usd_amount = 0) AND amount > 0")
	db.Exec("UPDATE users SET plan='Free' WHERE plan IS NULL OR plan=''")
	db.Exec("UPDATE methods SET layer='layer4' WHERE layer IS NULL OR layer=''")
	db.Exec("UPDATE wallets SET assigned_to=NULL WHERE assigned_to IS NOT NULL AND TRIM(assigned_to) = ''")
	db.Exec("UPDATE wallets SET status='Free' WHERE status IS NULL OR TRIM(status) = ''")
	nowUnix := time.Now().Unix()
	db.Exec(`
		UPDATE wallets
		SET status='Free'
		WHERE status NOT IN ('Free', 'Busy', '')
			AND (assigned_to IS NULL OR TRIM(assigned_to) = '')
			AND NOT EXISTS (
				SELECT 1 FROM deposits d
				WHERE d.address = wallets.address
					AND lower(d.status) = 'pending'
					AND (d.expires IS NULL OR d.expires = 0 OR d.expires > ?)
			)
	`, nowUnix)
	db.Exec(`
		UPDATE wallets
		SET status='Free'
		WHERE lower(status) = 'busy'
			AND (assigned_to IS NULL OR TRIM(assigned_to) = '')
			AND NOT EXISTS (
				SELECT 1 FROM deposits d
				WHERE d.address = wallets.address
					AND lower(d.status) = 'pending'
					AND (d.expires IS NULL OR d.expires = 0 OR d.expires > ?)
			)
	`, nowUnix)
	db.Exec(`
		UPDATE wallets
		SET assigned_to=NULL
		WHERE (status IS NULL OR TRIM(status) = '' OR lower(status) = 'free')
			AND assigned_to IS NOT NULL
			AND TRIM(assigned_to) != ''
			AND NOT EXISTS (
				SELECT 1 FROM deposits d
				WHERE d.address = wallets.address
					AND lower(d.status) = 'pending'
					AND (d.expires IS NULL OR d.expires = 0 OR d.expires > ?)
			)
	`, nowUnix)

	db.Exec("CREATE INDEX IF NOT EXISTS idx_deposits_user_id ON deposits(user_id);")
	db.Exec("CREATE INDEX IF NOT EXISTS idx_deposits_status ON deposits(status);")
	db.Exec("CREATE INDEX IF NOT EXISTS idx_sessions_username ON sessions(username);")
	db.Exec("CREATE INDEX IF NOT EXISTS idx_tickets_user_id ON tickets(user_id);")
	db.Exec("CREATE INDEX IF NOT EXISTS idx_activity_ts ON activity_logs(ts_unix);")
	db.Exec("CREATE INDEX IF NOT EXISTS idx_activity_action ON activity_logs(action);")
	db.Exec("CREATE INDEX IF NOT EXISTS idx_activity_actor ON activity_logs(actor_type, username);")
	db.Exec("CREATE INDEX IF NOT EXISTS idx_referral_credits_referrer ON referral_credits(referrer);")

	db.Exec("INSERT OR IGNORE INTO plans (name, concurrents, max_time, vip, api) VALUES ('Free', 1, 60, 0, 0)")

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
		pass, fromEnv := initialAdminPassword()
		hashedPass, err := generatePasswordHash(pass)
		if err != nil {
			log.Fatal("Failed to hash admin password:", err)
		}
		apiToken, apiFromEnv := initialAdminAPIToken()
		_, err = db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", "admin", hashedPass, "God", "Active", apiToken, "user#0001", 999.0, "ADMIN", "", 0.0, 0)
		if err != nil {
			log.Fatal("Failed to insert admin user:", err)
		}
		if fromEnv {
			log.Printf("Admin password initialized from TITAN_ADMIN_PASSWORD.")
		} else {
			log.Printf("Generated admin password: %s", pass)
		}
		if apiFromEnv {
			log.Printf("Admin API token initialized from TITAN_ADMIN_API_TOKEN.")
		}
	}
	rotateDefaultAdminAPIToken()
	migrateWalletPrivateKeys()
}

func initialAdminPassword() (string, bool) {
	if pass := os.Getenv("TITAN_ADMIN_PASSWORD"); pass != "" {
		return pass, true
	}
	return generateToken() + generateToken(), false
}

func initialAdminAPIToken() (string, bool) {
	if tok, ok := adminAPITokenFromEnv(); ok {
		return tok, true
	}
	return generateToken() + generateToken(), false
}

func adminAPITokenFromEnv() (string, bool) {
	tok := strings.TrimSpace(os.Getenv("TITAN_ADMIN_API_TOKEN"))
	if tok == "" || tok == defaultAdminAPIToken {
		return "", false
	}
	return tok, true
}

func rotateDefaultAdminAPIToken() {
	var apiToken string
	if err := db.QueryRow("SELECT api_token FROM users WHERE username='admin'").Scan(&apiToken); err != nil {
		return
	}
	if apiToken != defaultAdminAPIToken {
		return
	}
	newToken, fromEnv := initialAdminAPIToken()
	if newToken == "" || newToken == defaultAdminAPIToken {
		newToken = generateToken() + generateToken()
	}
	if _, err := db.Exec("UPDATE users SET api_token=? WHERE username='admin'", newToken); err != nil {
		return
	}
	if fromEnv {
		log.Printf("Admin API token rotated from TITAN_ADMIN_API_TOKEN.")
	} else {
		log.Printf("Admin API token rotated.")
	}
}

func migrateWalletPrivateKeys() {
	if _, ok := walletEncryptionKey(); !ok {
		return
	}
	rows, err := db.Query("SELECT address, private_key FROM wallets WHERE private_key IS NOT NULL AND private_key != ''")
	if err != nil {
		return
	}
	type walletRow struct {
		address string
		key     string
	}
	var pending []walletRow
	for rows.Next() {
		var address string
		var key string
		if err := rows.Scan(&address, &key); err != nil {
			continue
		}
		if strings.HasPrefix(key, walletKeyPrefix) {
			continue
		}
		pending = append(pending, walletRow{address: address, key: key})
	}
	rows.Close()
	for _, row := range pending {
		enc, err := encryptWalletPrivateKey(row.key)
		if err != nil {
			continue
		}
		_, _ = db.Exec("UPDATE wallets SET private_key=? WHERE address=?", enc, row.address)
	}
}
