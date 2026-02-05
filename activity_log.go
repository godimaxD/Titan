package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

const (
	actorTypeUser   = "USER"
	actorTypeAdmin  = "ADMIN"
	actorTypeSystem = "SYSTEM"

	severityInfo  = "INFO"
	severityWarn  = "WARN"
	severityError = "ERROR"
)

type ActivityLogEntry struct {
	Timestamp   string                 `json:"timestamp"`
	ActorType   string                 `json:"actor_type"`
	ActorID     string                 `json:"actor_id,omitempty"`
	Username    string                 `json:"username,omitempty"`
	Action      string                 `json:"action"`
	Severity    string                 `json:"severity"`
	RequestID   string                 `json:"request_id"`
	IP          string                 `json:"ip,omitempty"`
	UserAgent   string                 `json:"user_agent,omitempty"`
	ResourceIDs map[string]string      `json:"resource_ids,omitempty"`
	Message     string                 `json:"message"`
	Metadata    map[string]interface{} `json:"metadata,omitempty"`
}

type ActivityLogger struct {
	mu          sync.Mutex
	dir         string
	file        *os.File
	writer      *bufio.Writer
	currentDate string
}

var (
	activityLogger *ActivityLogger
	activityLogDir = "./data"
)

func initActivityLogger() error {
	logger, err := newActivityLogger(activityLogDir)
	if err != nil {
		return err
	}
	activityLogger = logger
	return nil
}

func newActivityLogger(dir string) (*ActivityLogger, error) {
	if dir == "" {
		return nil, errors.New("activity log dir missing")
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return nil, fmt.Errorf("create log dir: %w", err)
	}
	now := time.Now().UTC().Format("2006-01-02")
	filePath := filepath.Join(dir, "activity.log")
	file, err := os.OpenFile(filePath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, fmt.Errorf("open activity log: %w", err)
	}
	return &ActivityLogger{
		dir:         dir,
		file:        file,
		writer:      bufio.NewWriterSize(file, 32*1024),
		currentDate: now,
	}, nil
}

func (l *ActivityLogger) rotateIfNeeded(now time.Time) error {
	dateStr := now.UTC().Format("2006-01-02")
	if dateStr == l.currentDate {
		return nil
	}
	if l.writer != nil {
		_ = l.writer.Flush()
	}
	if l.file != nil {
		_ = l.file.Close()
	}
	oldPath := filepath.Join(l.dir, "activity.log")
	rotated := filepath.Join(l.dir, fmt.Sprintf("activity-%s.log", l.currentDate))
	if _, err := os.Stat(oldPath); err == nil {
		_ = os.Rename(oldPath, rotated)
	}
	file, err := os.OpenFile(oldPath, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o644)
	if err != nil {
		return fmt.Errorf("open activity log: %w", err)
	}
	l.file = file
	l.writer = bufio.NewWriterSize(file, 32*1024)
	l.currentDate = dateStr
	return nil
}

func (l *ActivityLogger) writeEntry(entry ActivityLogEntry) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now().UTC()
	if err := l.rotateIfNeeded(now); err != nil {
		return
	}
	payload, err := json.Marshal(entry)
	if err != nil {
		return
	}
	_, _ = l.writer.Write(append(payload, '\n'))
	_ = l.writer.Flush()
}

func LogActivity(r *http.Request, entry ActivityLogEntry) {
	if entry.Action == "" || entry.Severity == "" || entry.ActorType == "" {
		return
	}
	now := time.Now().UTC()
	entry.Timestamp = now.Format(time.RFC3339)
	if entry.RequestID == "" && r != nil {
		entry.RequestID = requestIDFromContext(r.Context())
	}
	if r != nil {
		if entry.IP == "" {
			entry.IP = clientIP(r)
		}
		if entry.UserAgent == "" {
			entry.UserAgent = r.UserAgent()
		}
	}
	entry.Metadata = sanitizeLogMetadata(entry.Metadata)
	entry.Message = strings.TrimSpace(entry.Message)
	if entry.Message == "" {
		entry.Message = entry.Action
	}

	if activityLogger != nil {
		activityLogger.writeEntry(entry)
	}
	if db != nil {
		_ = insertActivityLog(entry, now)
	}
}

func sanitizeLogMetadata(in map[string]interface{}) map[string]interface{} {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]interface{}, len(in))
	for k, v := range in {
		lk := strings.ToLower(k)
		if strings.Contains(lk, "password") || strings.Contains(lk, "token") || strings.Contains(lk, "secret") ||
			strings.Contains(lk, "private") || strings.Contains(lk, "csrf") || strings.Contains(lk, "authorization") {
			continue
		}
		out[k] = v
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

func insertActivityLog(entry ActivityLogEntry, now time.Time) error {
	resourceJSON := ""
	if len(entry.ResourceIDs) > 0 {
		if bytes, err := json.Marshal(entry.ResourceIDs); err == nil {
			resourceJSON = string(bytes)
		}
	}
	metadataJSON := ""
	if len(entry.Metadata) > 0 {
		if bytes, err := json.Marshal(entry.Metadata); err == nil {
			metadataJSON = string(bytes)
		}
	}
	_, err := db.Exec(`INSERT INTO activity_logs
		(timestamp, ts_unix, actor_type, actor_id, username, action, severity, request_id, ip, user_agent, message, resource_ids, metadata)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		entry.Timestamp,
		now.Unix(),
		entry.ActorType,
		entry.ActorID,
		entry.Username,
		entry.Action,
		entry.Severity,
		entry.RequestID,
		entry.IP,
		entry.UserAgent,
		entry.Message,
		resourceJSON,
		metadataJSON,
	)
	return err
}

func maskAddress(addr string) string {
	addr = strings.TrimSpace(addr)
	if len(addr) <= 8 {
		return addr
	}
	return fmt.Sprintf("%s...%s", addr[:4], addr[len(addr)-4:])
}
