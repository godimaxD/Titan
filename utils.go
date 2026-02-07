package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"html/template"
	"log"
	"math"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/argon2"
)

// --- UTILS ---

const (
	csrfCookieName   = "csrf_token"
	walletKeyPrefix  = "enc:"
	walletKeyEnvName = "TITAN_WALLET_KEY"
)

var (
	errNoUsableWallets   = errors.New("no usable wallets")
	errInvalidWalletRows = errors.New("invalid wallet rows")
	errWalletReservation = errors.New("wallet reservation conflict")
)

const walletUsableSQL = `
	TRIM(address) != ''
	AND TRIM(private_key) != ''
	AND (assigned_to IS NULL OR TRIM(assigned_to) = '')
	AND (status IS NULL OR TRIM(status) = '' OR lower(status) = 'free')
	AND NOT EXISTS (
		SELECT 1 FROM deposits d
		WHERE d.address = wallets.address
			AND lower(d.status) = 'pending'
			AND (d.expires IS NULL OR d.expires = 0 OR d.expires > ?)
	)
`

const walletReservationMaxRetries = 3

type walletDiagnostics struct {
	TotalWallets    int `json:"total_wallets"`
	UsableWallets   int `json:"usable_wallets"`
	BusyWallets     int `json:"busy_wallets"`
	MissingAddress  int `json:"missing_address"`
	MissingKey      int `json:"missing_key"`
	OrphanedWallets int `json:"orphaned_wallets"`
}

type depositErrorLog struct {
	Event       string             `json:"event"`
	Operation   string             `json:"operation"`
	DepositID   string             `json:"deposit_id,omitempty"`
	WalletID    int64              `json:"wallet_id,omitempty"`
	UserID      string             `json:"user_id,omitempty"`
	Category    string             `json:"category"`
	Error       string             `json:"error"`
	Diagnostics *walletDiagnostics `json:"diagnostics,omitempty"`
}

type walletCandidate struct {
	RowID      int64
	Address    string
	Status     string
	AssignedTo string
	PrivateKey string
}

func renderTemplate(w http.ResponseWriter, tmpl string, data interface{}) {
	// Use html/template to ensure proper contextual auto-escaping.
	t, err := template.ParseFiles("templates/"+tmpl, "templates/base_style.html")
	if err != nil {
		log.Printf("Template error (%s): %v", tmpl, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
	if err := t.Execute(w, data); err != nil {
		log.Printf("Template execute error (%s): %v", tmpl, err)
		http.Error(w, "Internal Server Error", http.StatusInternalServerError)
		return
	}
}

func applyEnvConfig() {
	if val := os.Getenv("TRUST_PROXY"); val != "" {
		cfg.TrustProxy = parseEnvBool(val)
	}
	if val := os.Getenv("FORCE_SECURE_COOKIES"); val != "" {
		cfg.ForceSecureCookies = parseEnvBool(val)
	}
}

func parseEnvBool(val string) bool {
	switch strings.ToLower(strings.TrimSpace(val)) {
	case "1", "true", "yes", "y", "on":
		return true
	default:
		return false
	}
}

func formatIntWithCommas(n int64) string {
	sign := ""
	if n < 0 {
		sign = "-"
		n = -n
	}
	s := strconv.FormatInt(n, 10)
	if len(s) <= 3 {
		return sign + s
	}
	var b strings.Builder
	prefix := len(s) % 3
	if prefix == 0 {
		prefix = 3
	}
	b.WriteString(s[:prefix])
	for i := prefix; i < len(s); i += 3 {
		b.WriteByte(',')
		b.WriteString(s[i : i+3])
	}
	return sign + b.String()
}

func isSecureRequest(r *http.Request) bool {
	if cfg.ForceSecureCookies {
		return true
	}
	if r == nil {
		return false
	}
	if r.TLS != nil {
		return true
	}
	if cfg.TrustProxy && isForwardedHTTPS(r) {
		return true
	}
	return false
}

func isForwardedHTTPS(r *http.Request) bool {
	if r == nil {
		return false
	}
	if proto := firstForwardedProto(r.Header.Get("X-Forwarded-Proto")); strings.EqualFold(proto, "https") {
		return true
	}
	return forwardedHeaderProtoHTTPS(r.Header.Get("Forwarded"))
}

func firstForwardedProto(headerVal string) string {
	if headerVal == "" {
		return ""
	}
	parts := strings.Split(headerVal, ",")
	if len(parts) == 0 {
		return ""
	}
	return strings.TrimSpace(parts[0])
}

func forwardedHeaderProtoHTTPS(headerVal string) bool {
	if headerVal == "" {
		return false
	}
	entries := strings.Split(headerVal, ",")
	for _, entry := range entries {
		params := strings.Split(entry, ";")
		for _, param := range params {
			kv := strings.SplitN(strings.TrimSpace(param), "=", 2)
			if len(kv) != 2 {
				continue
			}
			if !strings.EqualFold(kv[0], "proto") {
				continue
			}
			val := strings.Trim(kv[1], "\"")
			if strings.EqualFold(val, "https") {
				return true
			}
		}
	}
	return false
}

func roundFloat(val float64, precision uint) float64 {
	ratio := math.Pow(10, float64(precision))
	return math.Round(val*ratio) / ratio
}

func Sanitize(input string) string { return html.EscapeString(input) }

func hashIdentifier(input string) string {
	input = strings.TrimSpace(input)
	if input == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(input))
	return fmt.Sprintf("sha256:%x", sum[:4])
}

func setCSRFCookie(w http.ResponseWriter, r *http.Request, token string) {
	secure := isSecureRequest(r)
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

func ensureCSRFCookie(w http.ResponseWriter, r *http.Request) string {
	if r != nil {
		if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" {
			if token, ok := getOrCreateSessionCSRFToken(c.Value); ok && token != "" {
				setCSRFCookie(w, r, token)
				return token
			}
		}
		if c, err := r.Cookie(csrfCookieName); err == nil && c.Value != "" {
			return c.Value
		}
	}
	token := generateToken()
	setCSRFCookie(w, r, token)
	return token
}

func validateCSRF(r *http.Request) bool {
	if r == nil {
		return false
	}
	token := r.FormValue("csrf_token")
	if token == "" {
		token = r.Header.Get("X-CSRF-Token")
	}
	if token == "" {
		return false
	}
	if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" {
		if expected, ok := getSessionCSRFToken(c.Value); ok && expected != "" {
			return subtle.ConstantTimeCompare([]byte(token), []byte(expected)) == 1
		}
	}
	c, err := r.Cookie(csrfCookieName)
	if err != nil || c.Value == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(c.Value)) == 1
}

func writeJSONError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(map[string]string{
		"error": message,
		"code":  code,
	})
}

func isRequestBodyTooLarge(err error) bool {
	var maxErr *http.MaxBytesError
	return errors.As(err, &maxErr)
}

func setSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")

	// X-XSS-Protection is deprecated in modern browsers; leaving it out avoids a false sense of security.

	// Tighten CSP: remove unsafe-eval, keep unsafe-inline for now because templates/pages likely rely on inline scripts.
	// If you later move inline scripts to external files + nonces, remove unsafe-inline as well.
	w.Header().Set("Content-Security-Policy", "default-src 'self'; base-uri 'self'; frame-ancestors 'none'; object-src 'none'; script-src 'self' 'unsafe-inline' https://cdn.tailwindcss.com https://unpkg.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data: https://api.qrserver.com; connect-src 'self'; form-action 'self'")

	// Reasonable additional hardening headers (safe defaults)
	w.Header().Set("Referrer-Policy", "same-origin")
	w.Header().Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")
}

func getTrxPrice() float64 {
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Get(cfg.BinanceAPI)
	if err == nil {
		defer resp.Body.Close()
		var p BinancePrice
		if json.NewDecoder(resp.Body).Decode(&p) == nil {
			price, _ := strconv.ParseFloat(p.Price, 64)
			if price > cfg.MinTrxPrice && price < cfg.MaxTrxPrice {
				lastKnownTrxPrice = price
				return price
			}
		}
	}
	return lastKnownTrxPrice
}

func getIP(r *http.Request) string {
	atomic.AddUint64(&requestCounter, 1)
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

func clientIP(r *http.Request) string {
	if r == nil {
		return ""
	}
	ip, _, _ := net.SplitHostPort(r.RemoteAddr)
	return ip
}

type ArgonParams struct {
	memory, iterations, saltLength, keyLength uint32
	parallelism                               uint8
}

func generatePasswordHash(password string) (string, error) {
	p := &ArgonParams{memory: 64 * 1024, iterations: 3, parallelism: 2, saltLength: 16, keyLength: 32}
	salt := make([]byte, p.saltLength)
	rand.Read(salt)
	hash := argon2.IDKey([]byte(password), salt, p.iterations, p.memory, p.parallelism, p.keyLength)
	b64Salt := base64.RawStdEncoding.EncodeToString(salt)
	b64Hash := base64.RawStdEncoding.EncodeToString(hash)
	return fmt.Sprintf("$argon2id$v=%d$m=%d,t=%d,p=%d$%s$%s", argon2.Version, p.memory, p.iterations, p.parallelism, b64Salt, b64Hash), nil
}

func comparePasswordAndHash(password, hash string) (bool, error) {
	parts := strings.Split(hash, "$")
	if len(parts) != 6 {
		return false, fmt.Errorf("invalid hash")
	}
	var memory, iterations uint32
	var parallelism uint8
	fmt.Sscanf(parts[3], "m=%d,t=%d,p=%d", &memory, &iterations, &parallelism)
	salt, _ := base64.RawStdEncoding.DecodeString(parts[4])
	decodedHash, _ := base64.RawStdEncoding.DecodeString(parts[5])
	comparisonHash := argon2.IDKey([]byte(password), salt, iterations, memory, parallelism, uint32(len(decodedHash)))
	return (subtle.ConstantTimeCompare(decodedHash, comparisonHash) == 1), nil
}

func walletEncryptionKey() ([]byte, bool) {
	raw := strings.TrimSpace(os.Getenv(walletKeyEnvName))
	if raw == "" {
		return nil, false
	}
	sum := sha256.Sum256([]byte(raw))
	return sum[:], true
}

func encryptWalletPrivateKey(plain string) (string, error) {
	if plain == "" {
		return "", nil
	}
	if strings.HasPrefix(plain, walletKeyPrefix) {
		return plain, nil
	}
	key, ok := walletEncryptionKey()
	if !ok {
		return "", errors.New("wallet encryption key missing")
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return "", err
	}
	ciphertext := gcm.Seal(nil, nonce, []byte(plain), nil)
	blob := append(nonce, ciphertext...)
	return walletKeyPrefix + base64.RawStdEncoding.EncodeToString(blob), nil
}

func decryptWalletPrivateKey(enc string) (string, error) {
	if enc == "" {
		return "", nil
	}
	if !strings.HasPrefix(enc, walletKeyPrefix) {
		return enc, nil
	}
	key, ok := walletEncryptionKey()
	if !ok {
		return "", errors.New("wallet encryption key missing")
	}
	raw, err := base64.RawStdEncoding.DecodeString(strings.TrimPrefix(enc, walletKeyPrefix))
	if err != nil {
		return "", err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	if len(raw) < gcm.NonceSize() {
		return "", errors.New("invalid wallet key payload")
	}
	nonce := raw[:gcm.NonceSize()]
	ciphertext := raw[gcm.NonceSize():]
	plain, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", err
	}
	return string(plain), nil
}

func depositDebugEnabled() bool {
	return parseEnvBool(os.Getenv("TITAN_DEBUG")) || parseEnvBool(os.Getenv("DEBUG"))
}

func logDepositError(op, depositID string, walletID int64, userID, category string, err error, diagnostics *walletDiagnostics) {
	entry := depositErrorLog{
		Event:       "deposit_error",
		Operation:   op,
		DepositID:   depositID,
		WalletID:    walletID,
		UserID:      userID,
		Category:    category,
		Diagnostics: diagnostics,
	}
	if err != nil {
		entry.Error = err.Error()
	}
	payload, marshalErr := json.Marshal(entry)
	if marshalErr != nil {
		log.Printf("deposit_error marshal failed: op=%s category=%s err=%v", op, category, marshalErr)
		return
	}
	log.Printf("%s", payload)
}

func walletUsablePredicate() string {
	return walletUsableSQL
}

func walletRowUsable(row walletCandidate, activePending bool) bool {
	if strings.TrimSpace(row.Address) == "" {
		return false
	}
	if strings.TrimSpace(row.PrivateKey) == "" {
		return false
	}
	if strings.TrimSpace(row.AssignedTo) != "" {
		return false
	}
	status := strings.TrimSpace(row.Status)
	if status != "" && !strings.EqualFold(status, "Free") {
		return false
	}
	return !activePending
}

func hasActivePendingDepositTx(tx *sql.Tx, address string, now time.Time) (bool, error) {
	if strings.TrimSpace(address) == "" {
		return false, nil
	}
	var count int
	err := tx.QueryRow(`
		SELECT count(*)
		FROM deposits
		WHERE address = ?
			AND lower(status) = 'pending'
			AND (expires IS NULL OR expires = 0 OR expires > ?)
	`, address, now.Unix()).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

func selectUsableWalletTx(tx *sql.Tx, now time.Time) (walletCandidate, error) {
	query := fmt.Sprintf(`
		SELECT rowid,
			address,
			COALESCE(status, ''),
			COALESCE(assigned_to, ''),
			COALESCE(private_key, '')
		FROM wallets
		WHERE %s
		ORDER BY rowid ASC
		LIMIT 5
	`, walletUsablePredicate())
	rows, err := tx.Query(query, now.Unix())
	if err != nil {
		return walletCandidate{}, err
	}
	defer rows.Close()
	found := false
	for rows.Next() {
		found = true
		var row walletCandidate
		if err := rows.Scan(&row.RowID, &row.Address, &row.Status, &row.AssignedTo, &row.PrivateKey); err != nil {
			return walletCandidate{}, err
		}
		activePending, err := hasActivePendingDepositTx(tx, row.Address, now)
		if err != nil {
			return walletCandidate{}, err
		}
		if walletRowUsable(row, activePending) {
			return row, nil
		}
	}
	if err := rows.Err(); err != nil {
		return walletCandidate{}, err
	}
	if found {
		return walletCandidate{}, errInvalidWalletRows
	}
	return walletCandidate{}, errNoUsableWallets
}

func countUsableWalletsTx(tx *sql.Tx, now time.Time) (int, error) {
	query := fmt.Sprintf("SELECT count(*) FROM wallets WHERE %s", walletUsablePredicate())
	var count int
	if err := tx.QueryRow(query, now.Unix()).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func walletDiagnosticsTx(tx *sql.Tx, now time.Time) (*walletDiagnostics, error) {
	var diag walletDiagnostics
	if err := tx.QueryRow("SELECT count(*) FROM wallets").Scan(&diag.TotalWallets); err != nil {
		return nil, err
	}
	if usable, err := countUsableWalletsTx(tx, now); err == nil {
		diag.UsableWallets = usable
	}
	if err := tx.QueryRow(`
		SELECT count(*) FROM wallets
		WHERE lower(status)='busy'
			OR (assigned_to IS NOT NULL AND TRIM(assigned_to) != '')
	`).Scan(&diag.BusyWallets); err != nil {
		return nil, err
	}
	if err := tx.QueryRow("SELECT count(*) FROM wallets WHERE address IS NULL OR TRIM(address) = ''").Scan(&diag.MissingAddress); err != nil {
		return nil, err
	}
	if err := tx.QueryRow("SELECT count(*) FROM wallets WHERE private_key IS NULL OR TRIM(private_key) = ''").Scan(&diag.MissingKey); err != nil {
		return nil, err
	}
	if err := tx.QueryRow(`
		SELECT count(*) FROM wallets
		WHERE assigned_to IS NOT NULL
			AND TRIM(assigned_to) != ''
			AND NOT EXISTS (
				SELECT 1 FROM deposits d
				WHERE d.id = wallets.assigned_to
					AND lower(d.status) = 'pending'
					AND (d.expires IS NULL OR d.expires = 0 OR d.expires > ?)
			)
	`, now.Unix()).Scan(&diag.OrphanedWallets); err != nil {
		return nil, err
	}
	return &diag, nil
}

func reserveUsableWalletTx(tx *sql.Tx, now time.Time, depositID string) (walletCandidate, error) {
	for attempt := 0; attempt < walletReservationMaxRetries; attempt++ {
		res, err := tx.Exec(fmt.Sprintf(`
			UPDATE wallets
			SET status='Busy', assigned_to=?
			WHERE rowid = (
				SELECT rowid FROM wallets
				WHERE %s
				ORDER BY rowid ASC
				LIMIT 1
			)
			AND %s
		`, walletUsablePredicate(), walletUsablePredicate()), depositID, now.Unix(), now.Unix())
		if err != nil {
			if isSQLiteLockError(err) {
				time.Sleep(10 * time.Millisecond)
				continue
			}
			return walletCandidate{}, err
		}
		if rows, _ := res.RowsAffected(); rows > 0 {
			var row walletCandidate
			if err := tx.QueryRow(`
				SELECT rowid,
					address,
					COALESCE(status, ''),
					COALESCE(assigned_to, ''),
					COALESCE(private_key, '')
				FROM wallets
				WHERE assigned_to = ?
				LIMIT 1
			`, depositID).Scan(&row.RowID, &row.Address, &row.Status, &row.AssignedTo, &row.PrivateKey); err != nil {
				return walletCandidate{}, err
			}
			return row, nil
		}
		if usable, err := countUsableWalletsTx(tx, now); err == nil && usable == 0 {
			return walletCandidate{}, errNoUsableWallets
		}
	}
	return walletCandidate{}, errWalletReservation
}

func isSQLiteLockError(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "database is locked") ||
		strings.Contains(msg, "database table is locked") ||
		strings.Contains(msg, "database is busy") ||
		strings.Contains(msg, "busy")
}

func expirePendingDepositsTx(tx *sql.Tx, now time.Time) error {
	if _, err := tx.Exec("UPDATE deposits SET status='Expired' WHERE lower(status)='pending' AND expires < ? AND expires != 0", now.Unix()); err != nil {
		return err
	}
	_, err := tx.Exec(`
		UPDATE wallets
		SET status='Free', assigned_to=NULL
		WHERE assigned_to IN (SELECT id FROM deposits WHERE lower(status)='expired' AND expires < ?)
			AND NOT EXISTS (
				SELECT 1 FROM deposits d
				WHERE d.address = wallets.address
					AND lower(d.status) = 'pending'
					AND (d.expires IS NULL OR d.expires = 0 OR d.expires > ?)
			)
	`, now.Unix(), now.Unix())
	return err
}

func releaseWalletForDepositTx(tx *sql.Tx, depositID string, now time.Time) error {
	_, err := tx.Exec(`
		UPDATE wallets
		SET status='Free', assigned_to=NULL
		WHERE (assigned_to = ? OR address = (SELECT address FROM deposits WHERE id = ?))
			AND NOT EXISTS (
				SELECT 1 FROM deposits d
				WHERE d.address = wallets.address
					AND lower(d.status) = 'pending'
					AND (d.expires IS NULL OR d.expires = 0 OR d.expires > ?)
			)
	`, depositID, depositID, now.Unix())
	return err
}

func generateToken() string {
	b := make([]byte, 32)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}
func generateUniqueRefCode() (string, error) {
	for i := 0; i < 5; i++ {
		code := generateToken()[:8]
		var count int
		if err := db.QueryRow("SELECT count(*) FROM users WHERE ref_code=?", code).Scan(&count); err != nil {
			return "", err
		}
		if count == 0 {
			return code, nil
		}
	}
	return "", fmt.Errorf("unable to generate unique ref code")
}
func generateID() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(99999))
	return fmt.Sprintf("%d", n.Int64()+10000)
}
func getUptime() string { return time.Since(startTime).String() }
func formatUptime(d time.Duration) string {
	if d < time.Minute {
		return fmt.Sprintf("%ds", int(d.Seconds()))
	}
	days := d / (24 * time.Hour)
	d -= days * 24 * time.Hour
	hours := d / time.Hour
	d -= hours * time.Hour
	minutes := d / time.Minute
	if days > 0 {
		return fmt.Sprintf("%dd %dh %dm", days, hours, minutes)
	}
	if hours > 0 {
		return fmt.Sprintf("%dh %dm", hours, minutes)
	}
	return fmt.Sprintf("%dm", minutes)
}

func formatBytes(bytes uint64) string {
	const unit = 1024 * 1024
	return fmt.Sprintf("%.2f MB", float64(bytes)/unit)
}
func getPlanConfig(n string) PlanConfig {
	var p PlanConfig
	if err := db.QueryRow("SELECT concurrents, max_time, vip, api FROM plans WHERE name=?", n).Scan(&p.Concurrents, &p.MaxTime, &p.VIP, &p.API); err != nil {
		return PlanConfig{Concurrents: 1, MaxTime: 60, VIP: false, API: false}
	}
	return p
}
func effectivePlanName(plan string) string {
	plan = strings.TrimSpace(plan)
	if plan == "" {
		return "Free"
	}
	return plan
}
func getReferralEarnings(username string) float64 {
	var total sql.NullFloat64
	if err := db.QueryRow("SELECT COALESCE(SUM(amount), 0) FROM referral_credits WHERE referrer=?", username).Scan(&total); err != nil {
		return 0
	}
	if total.Valid {
		return roundFloat(total.Float64, 2)
	}
	return 0
}

func normalizeBlacklistTarget(input string) (string, bool) {
	raw := strings.TrimSpace(input)
	if raw == "" {
		return "", false
	}
	host := raw
	if strings.Contains(raw, "://") {
		if parsed, err := url.Parse(raw); err == nil && parsed.Host != "" {
			host = parsed.Hostname()
		}
	}
	host = strings.TrimSpace(host)
	if host == "" {
		return "", false
	}
	if strings.HasPrefix(host, "[") {
		if h, _, err := net.SplitHostPort(host); err == nil {
			host = h
		} else {
			host = strings.TrimPrefix(host, "[")
			host = strings.TrimSuffix(host, "]")
		}
	} else if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.TrimSpace(host)
	host = strings.TrimRight(host, ".")
	if host == "" {
		return "", false
	}
	return strings.ToLower(host), true
}

func logRateLimit(r *http.Request, ip, username string) {
	path := ""
	if r != nil && r.URL != nil {
		path = r.URL.Path
	}
	if username != "" {
		log.Printf("event=rate_limit ip=%s path=%s username=%s", ip, path, username)
		return
	}
	log.Printf("event=rate_limit ip=%s path=%s", ip, path)
}

func logBlacklistReject(r *http.Request, ip, username, target string) {
	path := ""
	if r != nil && r.URL != nil {
		path = r.URL.Path
	}
	if username != "" {
		log.Printf("event=blacklist_reject ip=%s path=%s username=%s target=%s", ip, path, username, target)
		return
	}
	log.Printf("event=blacklist_reject ip=%s path=%s target=%s", ip, path, target)
}

func logLogoutMismatch(r *http.Request, ip, username string) {
	path := ""
	if r != nil && r.URL != nil {
		path = r.URL.Path
	}
	if username != "" {
		log.Printf("event=logout_mismatch ip=%s path=%s username=%s", ip, path, username)
		return
	}
	log.Printf("event=logout_mismatch ip=%s path=%s", ip, path)
}

func isBlacklisted(t string) bool {
	t = strings.TrimSpace(t)
	if t == "" {
		return false
	}
	var direct bool
	if err := db.QueryRow("SELECT 1 FROM blacklist WHERE lower(target)=lower(?)", t).Scan(&direct); err == nil && direct {
		return true
	}
	normalized, ok := normalizeBlacklistTarget(t)
	if !ok || normalized == "" {
		return false
	}
	var normalizedMatch bool
	if err := db.QueryRow("SELECT 1 FROM blacklist WHERE lower(target)=lower(?)", normalized).Scan(&normalizedMatch); err == nil && normalizedMatch {
		return true
	}
	return false
}
func getUserByToken(t string) (User, bool) {
	var usr User
	err := db.QueryRow("SELECT username, plan, status, balance, api_token, user_id FROM users WHERE api_token=?", t).
		Scan(&usr.Username, &usr.Plan, &usr.Status, &usr.Balance, &usr.ApiToken, &usr.UserID)
	return usr, err == nil
}
func getUser(u string) (User, bool) {
	var usr User
	err := db.QueryRow("SELECT username, password, plan, status, balance, ref_code, referred_by, ref_earnings FROM users WHERE username=?", u).Scan(&usr.Username, &usr.Password, &usr.Plan, &usr.Status, &usr.Balance, &usr.RefCode, &usr.ReferredBy, &usr.RefEarnings)
	return usr, err == nil
}

func getUserIDByUsername(username string) string {
	if username == "" {
		return ""
	}
	var userID string
	if err := db.QueryRow("SELECT user_id FROM users WHERE username=?", username).Scan(&userID); err != nil {
		return ""
	}
	return userID
}
func generateTronWallet() (string, string) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	privBytes := priv.D.Bytes()
	return fmt.Sprintf("%x", privBytes), ""
}
func resetC2() {
	client := &http.Client{Timeout: 10 * time.Second}
	client.Get(cfg.C2Host + "/admin/stop_all?token=" + cfg.C2Key)
}
