package main

import (
	"database/sql"
	"sync"
	"time"
)

// --- CONFIG ---
type AppConfig struct {
	SessionDuration    time.Duration
	C2Host             string
	C2Key              string
	BinanceAPI         string
	MaxTrxPrice        float64
	MinTrxPrice        float64
	ReferralPercent    float64
	TrustProxy         bool
	ForceSecureCookies bool
}

// --- DATA STRUCTURES ---
type User struct {
	Username, Password, Plan, Status, ApiToken, UserID string
	Balance                                            float64
	RefCode                                            string
	ReferredBy                                         string
	RefEarnings                                        float64
}
type TicketMessage struct {
	Sender, Content, Time string
	IsAdmin               bool
}
type Ticket struct {
	ID, UserID, Category, Subject, Status string
	Messages                              []TicketMessage
	LastUpdate                            time.Time
}
type RedeemCode struct {
	Code, Plan string
	Used       bool
}
type PlanConfig struct {
	Concurrents, MaxTime int
	VIP, API             bool
}
type Product struct {
	ID             int
	Name           string
	Price          float64
	Time           int
	Concurrents    int
	VIP, APIAccess bool
}
type Wallet struct{ Address, PrivateKey, Status, AssignedTo string }
type Deposit struct {
	ID, UserID            string
	Amount                float64
	UsdAmount             float64
	Address, Status, Date string
	Expires               time.Time
	ConfirmedAt           sql.NullString
	TxID                  sql.NullString
	Fee                   sql.NullFloat64
	Notes                 sql.NullString
}
type AttackData struct {
	ID, UserID, Target, Method, Port, Concurrency, Location string
	Duration                                                int
	StartTime, EndTime                                      time.Time
}
type Announcement struct{ Title, Message string }

type PageData struct {
	Username, UserPlan, CurrentPage, UsernameInitials, ApiToken, UserIDDisplay string
	UserBalance, RefEarnings                                                   float64
	RefCode                                                                    string
	ReferredBy                                                                 string
	IsAdmin, AutoConfirm                                                       bool
	Announcements                                                              []Announcement
	MethodsJSON                                                                string
	Methods                                                                    map[string][]string
	Products                                                                   []Product
	BlockedIPs, Regions, RPS                                                   int
	Uptime                                                                     string
	ActiveAttacks                                                              int
	PlanConfigs                                                                map[string]PlanConfig
	Tickets                                                                    []Ticket
	CurrentTicket                                                              Ticket
	Deposits                                                                   []Deposit
	MaxTime                                                                    int
	MaxConcurrents                                                             int
	IsVIP                                                                      bool
	CaptchaId                                                                  string
	CsrfToken                                                                  string
	RefCount                                                                   int
	FlashMessage                                                               string
	FlashType                                                                  string
	RequestID                                                                  string
	FormError                                                                  string
	FieldErrors                                                                map[string]string
	FormValues                                                                 map[string]string
	FreePlan                                                                   PlanConfig
	ReferralCode                                                               string
	ReferralLocked                                                             bool
	StatusUptime                                                               string
	StatusStartTime                                                            string
	StatusServerTime                                                           string
	StatusServerTimezone                                                       string
	StatusAppVersion                                                           string
	StatusDBHealthy                                                            bool
	StatusDBError                                                              string
	StatusTotalUsers                                                           int
	StatusTotalDeposits                                                        int
	StatusDepositPending                                                       int
	StatusDepositPaid                                                          int
	StatusDepositRejected                                                      int
	StatusDepositExpired                                                       int
	StatusTotalPurchases                                                       int
	StatusGoVersion                                                            string
	StatusOSArch                                                               string
	StatusMemAlloc                                                             string
	StatusMemSys                                                               string
	StatusActiveAttacksAvailable                                               bool
}

type InvoiceData struct {
	ID, Address      string
	Amount           float64
	UsdAmount        float64
	ExpiresInSeconds int
	Status           string
}
type PaymentPageData struct {
	ID, Address      string
	Amount           float64
	UsdAmount        float64
	ExpiresInSeconds int
	ExpiresAt        string
	Status           string
	Currency         string
	FlashMessage     string
	FlashType        string
}

type ReceiptData struct {
	ID          string
	Username    string
	UserID      string
	Address     string
	Amount      float64
	UsdAmount   float64
	Status      string
	CreatedAt   string
	ConfirmedAt string
	TxID        string
	Fee         float64
	Notes       string
	Currency    string
	IsDownload  bool
}
type AdminData struct {
	Username, Uptime                         string
	TotalUsers, TotalAttacks, RunningAttacks int
	Deposits                                 []Deposit
	PlanConfigs                              map[string]PlanConfig
	Tickets                                  []Ticket
	CurrentTicket                            Ticket
	Users                                    []User
	Products                                 []Product
	Wallets                                  []Wallet
	RPS                                      int
	CurrentView                              string
	Blacklist                                []BlacklistEntry
	ActiveAttacksList                        []AttackData
	CsrfToken                                string
}

type BlacklistEntry struct{ Target, Reason, Date string }
type ApiReq struct {
	Target, Method, Port, Time, Concurrency, Location, Layer string
}
type BinancePrice struct {
	Price string `json:"price"`
}
type ClientLimiter struct {
	limiter  *RateBucket
	lastSeen time.Time
}
type RateBucket struct {
	tokens, capacity, refillRate float64
	lastRefill                   time.Time
	mu                           sync.Mutex
}

type RateLimitEntry struct {
	Count     int
	LastReset int64
}
