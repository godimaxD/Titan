package main

import (
	"context"
	"fmt"
	"net/http"
)

type requestIDKey struct{}

func wrapHandler(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		reqID := r.Header.Get("X-Request-ID")
		if reqID == "" {
			reqID = generateToken()
		}
		ctx := context.WithValue(r.Context(), requestIDKey{}, reqID)
		r = r.WithContext(ctx)
		w.Header().Set("X-Request-ID", reqID)
		defer func() {
			if rec := recover(); rec != nil {
				LogActivity(r, ActivityLogEntry{
					ActorType: actorTypeSystem,
					Action:    "SYSTEM_PANIC",
					Severity:  severityError,
					Message:   "Recovered from panic in request handler.",
					Metadata: map[string]interface{}{
						"panic": fmt.Sprintf("%v", rec),
						"path":  r.URL.Path,
					},
				})
				http.Error(w, "Internal Server Error", http.StatusInternalServerError)
			}
		}()
		next(w, r)
	}
}

func requestIDFromContext(ctx context.Context) string {
	if ctx == nil {
		return ""
	}
	if v := ctx.Value(requestIDKey{}); v != nil {
		if s, ok := v.(string); ok {
			return s
		}
	}
	return ""
}
