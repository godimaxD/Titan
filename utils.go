package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"html"
	"html/template"
	"log"
	"math"
	"math/big"
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/crypto/argon2"
)

// --- UTILS ---

const csrfCookieName = "csrf_token"

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
	secure := true
	if r != nil && r.TLS == nil {
		secure = false
	}
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
	token := r.Header.Get("X-CSRF-Token")
	if token == "" {
		if !isJSONRequest(r) {
			token = r.FormValue("csrf_token")
		}
	}
	if token == "" {
		return false
	}
	return subtle.ConstantTimeCompare([]byte(token), []byte(c.Value)) == 1
}

func isJSONRequest(r *http.Request) bool {
	if r == nil {
		return false
	}
	contentType := strings.ToLower(r.Header.Get("Content-Type"))
	return strings.HasPrefix(contentType, "application/json")
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

func generateToken() string { b := make([]byte, 16); rand.Read(b); return fmt.Sprintf("%x", b) }
func generateID() string {
	n, _ := rand.Int(rand.Reader, big.NewInt(99999))
	return fmt.Sprintf("%d", n.Int64()+10000)
}
func getUptime() string { return time.Since(startTime).String() }
func getPlanConfig(n string) PlanConfig {
	var p PlanConfig
	if err := db.QueryRow("SELECT concurrents, max_time FROM plans WHERE name=?", n).Scan(&p.Concurrents, &p.MaxTime); err != nil {
		return PlanConfig{Concurrents: 1, MaxTime: 60, VIP: false, API: false}
	}
	return p
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
func generateTronWallet() (string, string) {
	priv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	privBytes := priv.D.Bytes()
	return fmt.Sprintf("%x", privBytes), ""
}
func resetC2() {
	client := &http.Client{Timeout: 10 * time.Second}
	client.Get(cfg.C2Host + "/admin/stop_all?token=" + cfg.C2Key)
}
