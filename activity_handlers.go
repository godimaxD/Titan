package main

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

type ActivityLogSearchFilters struct {
	Query      string
	From       *time.Time
	To         *time.Time
	ActorType  string
	Username   string
	ActorID    string
	Actions    []string
	Severities []string
	ResourceID string
	Sort       string
	Page       int
	PageSize   int
}

type ActivityLogRecord struct {
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

func handleActivitySearch(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if !requireAdmin(w, r) {
		return
	}

	filters, err := parseActivityFilters(r)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}

	records, total, err := queryActivityLogs(filters)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "db_error", "Failed to fetch activity logs.")
		return
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"items":     records,
		"total":     total,
		"page":      filters.Page,
		"page_size": filters.PageSize,
	})
}

func handleActivityActions(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	w.Header().Set("Content-Type", "application/json")
	w.Header().Set("Cache-Control", "no-store")
	if !requireAdmin(w, r) {
		return
	}
	rows, err := db.Query("SELECT DISTINCT action FROM activity_logs ORDER BY action ASC")
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "db_error", "Failed to load actions.")
		return
	}
	defer rows.Close()
	var actions []string
	for rows.Next() {
		var action string
		if err := rows.Scan(&action); err == nil && action != "" {
			actions = append(actions, action)
		}
	}
	json.NewEncoder(w).Encode(map[string]interface{}{
		"actions": actions,
	})
}

func handleActivityExport(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	if !requireAdmin(w, r) {
		return
	}
	filters, err := parseActivityFilters(r)
	if err != nil {
		writeJSONError(w, http.StatusBadRequest, "bad_request", err.Error())
		return
	}
	filters.Page = 1
	filters.PageSize = 5000

	records, _, err := queryActivityLogs(filters)
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "db_error", "Failed to export activity logs.")
		return
	}

	format := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("format")))
	if format == "" {
		format = "jsonl"
	}
	filename := fmt.Sprintf("activity-export-%s.%s", time.Now().UTC().Format("20060102-150405"), format)
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))

	switch format {
	case "csv":
		w.Header().Set("Content-Type", "text/csv; charset=utf-8")
		writeActivityCSV(w, records)
	default:
		w.Header().Set("Content-Type", "application/jsonl; charset=utf-8")
		writeActivityJSONL(w, records)
	}
}

func handleActivityDownload(w http.ResponseWriter, r *http.Request) {
	setSecurityHeaders(w)
	if !requireAdmin(w, r) {
		return
	}
	scope := strings.ToLower(strings.TrimSpace(r.URL.Query().Get("scope")))
	if scope == "" {
		scope = "current"
	}
	logDir := activityLogDir
	if logDir == "" {
		writeJSONError(w, http.StatusInternalServerError, "server_error", "Log directory not configured.")
		return
	}
	var files []string
	if scope == "all" {
		matches, _ := filepath.Glob(filepath.Join(logDir, "activity*.log"))
		files = append(files, matches...)
	} else {
		files = append(files, filepath.Join(logDir, "activity.log"))
	}
	sort.Strings(files)
	filename := fmt.Sprintf("activity-logs-%s.log", time.Now().UTC().Format("20060102-150405"))
	w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")

	for _, path := range files {
		if !strings.HasPrefix(filepath.Clean(path), filepath.Clean(logDir)) {
			continue
		}
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		_, _ = w.Write(data)
		if len(data) > 0 && data[len(data)-1] != '\n' {
			_, _ = w.Write([]byte("\n"))
		}
	}
}

func writeActivityJSONL(w http.ResponseWriter, records []ActivityLogRecord) {
	encoder := json.NewEncoder(w)
	for _, r := range records {
		_ = encoder.Encode(r)
	}
}

func writeActivityCSV(w http.ResponseWriter, records []ActivityLogRecord) {
	cw := csv.NewWriter(w)
	_ = cw.Write([]string{"timestamp", "actor_type", "actor_id", "username", "action", "severity", "request_id", "ip", "user_agent", "message", "resource_ids", "metadata"})
	for _, r := range records {
		resourceJSON := ""
		if r.ResourceIDs != nil {
			if bytes, err := json.Marshal(r.ResourceIDs); err == nil {
				resourceJSON = string(bytes)
			}
		}
		metadataJSON := ""
		if r.Metadata != nil {
			if bytes, err := json.Marshal(r.Metadata); err == nil {
				metadataJSON = string(bytes)
			}
		}
		_ = cw.Write([]string{
			r.Timestamp,
			r.ActorType,
			r.ActorID,
			r.Username,
			r.Action,
			r.Severity,
			r.RequestID,
			r.IP,
			r.UserAgent,
			r.Message,
			resourceJSON,
			metadataJSON,
		})
	}
	cw.Flush()
}

func parseActivityFilters(r *http.Request) (ActivityLogSearchFilters, error) {
	q := r.URL.Query()
	filters := ActivityLogSearchFilters{
		Query:      strings.TrimSpace(q.Get("q")),
		ActorType:  strings.ToUpper(strings.TrimSpace(q.Get("actor_type"))),
		Username:   strings.TrimSpace(q.Get("username")),
		ActorID:    strings.TrimSpace(q.Get("actor_id")),
		ResourceID: strings.TrimSpace(q.Get("resource_id")),
		Sort:       strings.ToLower(strings.TrimSpace(q.Get("sort"))),
		Page:       1,
		PageSize:   50,
	}
	if filters.Sort != "asc" {
		filters.Sort = "desc"
	}
	if v := q.Get("page"); v != "" {
		if num, err := strconv.Atoi(v); err == nil && num > 0 {
			filters.Page = num
		}
	}
	if v := q.Get("page_size"); v != "" {
		if num, err := strconv.Atoi(v); err == nil && num > 0 && num <= 200 {
			filters.PageSize = num
		}
	}
	if fromStr := strings.TrimSpace(q.Get("from")); fromStr != "" {
		if t, err := time.Parse(time.RFC3339, fromStr); err == nil {
			filters.From = &t
		} else if t, err := time.Parse("2006-01-02T15:04", fromStr); err == nil {
			filters.From = &t
		} else {
			return filters, fmt.Errorf("invalid from timestamp")
		}
	}
	if toStr := strings.TrimSpace(q.Get("to")); toStr != "" {
		if t, err := time.Parse(time.RFC3339, toStr); err == nil {
			filters.To = &t
		} else if t, err := time.Parse("2006-01-02T15:04", toStr); err == nil {
			filters.To = &t
		} else {
			return filters, fmt.Errorf("invalid to timestamp")
		}
	}
	filters.Actions = parseCSVList(q["action"], q.Get("action"))
	filters.Severities = parseCSVList(q["severity"], q.Get("severity"))
	return filters, nil
}

func parseCSVList(values []string, fallback string) []string {
	var out []string
	for _, v := range values {
		for _, part := range strings.Split(v, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				out = append(out, part)
			}
		}
	}
	if len(out) == 0 && fallback != "" {
		for _, part := range strings.Split(fallback, ",") {
			part = strings.TrimSpace(part)
			if part != "" {
				out = append(out, part)
			}
		}
	}
	return out
}

func queryActivityLogs(filters ActivityLogSearchFilters) ([]ActivityLogRecord, int, error) {
	where := []string{"1=1"}
	args := []interface{}{}

	if filters.Query != "" {
		like := "%" + filters.Query + "%"
		where = append(where, "(message LIKE ? OR metadata LIKE ? OR resource_ids LIKE ? OR action LIKE ?)")
		args = append(args, like, like, like, like)
	}
	if filters.From != nil {
		where = append(where, "ts_unix >= ?")
		args = append(args, filters.From.UTC().Unix())
	}
	if filters.To != nil {
		where = append(where, "ts_unix <= ?")
		args = append(args, filters.To.UTC().Unix())
	}
	if filters.ActorType != "" {
		where = append(where, "actor_type = ?")
		args = append(args, filters.ActorType)
	}
	if filters.Username != "" {
		where = append(where, "username = ?")
		args = append(args, filters.Username)
	}
	if filters.ActorID != "" {
		where = append(where, "actor_id = ?")
		args = append(args, filters.ActorID)
	}
	if len(filters.Actions) > 0 {
		placeholders := strings.Repeat("?,", len(filters.Actions))
		where = append(where, fmt.Sprintf("action IN (%s)", strings.TrimSuffix(placeholders, ",")))
		for _, a := range filters.Actions {
			args = append(args, a)
		}
	}
	if len(filters.Severities) > 0 {
		placeholders := strings.Repeat("?,", len(filters.Severities))
		where = append(where, fmt.Sprintf("severity IN (%s)", strings.TrimSuffix(placeholders, ",")))
		for _, s := range filters.Severities {
			args = append(args, s)
		}
	}
	if filters.ResourceID != "" {
		like := "%" + filters.ResourceID + "%"
		where = append(where, "resource_ids LIKE ?")
		args = append(args, like)
	}

	whereClause := strings.Join(where, " AND ")
	var total int
	countQuery := fmt.Sprintf("SELECT COUNT(*) FROM activity_logs WHERE %s", whereClause)
	if err := db.QueryRow(countQuery, args...).Scan(&total); err != nil {
		return nil, 0, err
	}

	order := "DESC"
	if filters.Sort == "asc" {
		order = "ASC"
	}
	offset := (filters.Page - 1) * filters.PageSize
	query := fmt.Sprintf(`SELECT timestamp, actor_type, actor_id, username, action, severity, request_id, ip, user_agent, message, resource_ids, metadata
		FROM activity_logs WHERE %s ORDER BY ts_unix %s LIMIT ? OFFSET ?`, whereClause, order)
	args = append(args, filters.PageSize, offset)

	rows, err := db.Query(query, args...)
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	var records []ActivityLogRecord
	for rows.Next() {
		var rec ActivityLogRecord
		var resourceJSON, metadataJSON string
		if err := rows.Scan(&rec.Timestamp, &rec.ActorType, &rec.ActorID, &rec.Username, &rec.Action, &rec.Severity, &rec.RequestID, &rec.IP, &rec.UserAgent, &rec.Message, &resourceJSON, &metadataJSON); err != nil {
			continue
		}
		if resourceJSON != "" {
			_ = json.Unmarshal([]byte(resourceJSON), &rec.ResourceIDs)
		}
		if metadataJSON != "" {
			_ = json.Unmarshal([]byte(metadataJSON), &rec.Metadata)
		}
		records = append(records, rec)
	}
	return records, total, nil
}

func requireAdmin(w http.ResponseWriter, r *http.Request) bool {
	username, ok := validateSession(r)
	if !ok || username != "admin" {
		writeJSONError(w, http.StatusForbidden, "forbidden", "Admin access required.")
		return false
	}
	return true
}
