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

func ensureCSRFCookie(w http.ResponseWriter, r *http.Request) string {
	if r != nil {
		if c, err := r.Cookie(csrfCookieName); err == nil && c.Value != "" {
			return c.Value
		}
	}
	token := generateToken() + generateToken()
	secure := isSecureRequest(r)
	http.SetCookie(w, &http.Cookie{
		Name:     csrfCookieName,
		Value:    token,
		Path:     "/",
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
	return token
}

func validateCSRF(r *http.Request) bool {
	if r == nil {
		return false
	}
	c, err := r.Cookie(csrfCookieName)
	if err != nil || c.Value == "" {
		return false
	}
	token := r.FormValue("csrf_token")
	if token == "" {
		token = r.Header.Get("X-CSRF-Token")
	}
	if token == "" {
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
	`, walletUsableSQL)
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
	query := fmt.Sprintf("SELECT count(*) FROM wallets WHERE %s", walletUsableSQL)
	var count int
	if err := tx.QueryRow(query, now.Unix()).Scan(&count); err != nil {
		return 0, err
	}
	return count, nil
}

func logDepositWalletFailure(tx *sql.Tx, reason string, err error) {
	if !depositDebugEnabled() {
		return
	}
	var queryer interface {
		QueryRow(string, ...any) *sql.Row
		Query(string, ...any) (*sql.Rows, error)
	}
	if tx != nil {
		queryer = tx
	} else {
		queryer = db
	}
	var total int
	_ = queryer.QueryRow("SELECT count(*) FROM wallets").Scan(&total)
	usable := 0
	if tx != nil {
		if count, countErr := countUsableWalletsTx(tx, time.Now()); countErr == nil {
			usable = count
		}
	} else {
		query := fmt.Sprintf("SELECT count(*) FROM wallets WHERE %s", walletUsableSQL)
		_ = queryer.QueryRow(query, time.Now().Unix()).Scan(&usable)
	}
	samples := make([]string, 0, 3)
	rows, sampleErr := queryer.Query("SELECT rowid, address, COALESCE(status, ''), COALESCE(assigned_to, ''), COALESCE(private_key, '') FROM wallets ORDER BY rowid ASC LIMIT 3")
	if sampleErr == nil {
		defer rows.Close()
		for rows.Next() {
			var row walletCandidate
			if err := rows.Scan(&row.RowID, &row.Address, &row.Status, &row.AssignedTo, &row.PrivateKey); err != nil {
				continue
			}
			hasKey := strings.TrimSpace(row.PrivateKey) != ""
			samples = append(samples, fmt.Sprintf("{id:%d address:%s status:%s assigned_to:%s has_key:%t}", row.RowID, row.Address, row.Status, row.AssignedTo, hasKey))
		}
	}
	log.Printf("deposit wallet debug: reason=%s err=%v total_wallets=%d usable_wallets=%d sample=%v", reason, err, total, usable, samples)
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

func generateToken() string { b := make([]byte, 16); rand.Read(b); return fmt.Sprintf("%x", b) }
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
func isBlacklisted(t string) bool {
	var x bool
	db.QueryRow("SELECT 1 FROM blacklist WHERE target=?", t).Scan(&x)
	return x
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
