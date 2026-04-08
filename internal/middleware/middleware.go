// Package middleware contains HTTP middleware for security, authentication,
// rate limiting, and request lifecycle management.
package middleware

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/buadamlaz/sambaguard/internal/model"
	"github.com/buadamlaz/sambaguard/internal/service"
	"go.uber.org/zap"
	"golang.org/x/time/rate"
)

// ─── Context keys ─────────────────────────────────────────────────────────────

type contextKey string

const (
	ContextKeyClaims = contextKey("claims")
	ContextKeyIP     = contextKey("client_ip")
)

// ClaimsFromContext extracts JWT claims from a request context.
func ClaimsFromContext(ctx context.Context) *model.Claims {
	c, _ := ctx.Value(ContextKeyClaims).(*model.Claims)
	return c
}

// IPFromContext extracts the client IP from a request context.
func IPFromContext(ctx context.Context) string {
	ip, _ := ctx.Value(ContextKeyIP).(string)
	return ip
}

// ─── Auth middleware ──────────────────────────────────────────────────────────

// Auth validates the Bearer JWT access token in every protected request.
func Auth(authSvc *service.AuthService) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			token := extractBearer(r)
			if token == "" {
				writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "missing or malformed Authorization header")
				return
			}

			claims, err := authSvc.ValidateAccessToken(token)
			if err != nil {
				writeError(w, http.StatusUnauthorized, "INVALID_TOKEN", "invalid or expired access token")
				return
			}

			ctx := context.WithValue(r.Context(), ContextKeyClaims, claims)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RequireRole returns middleware that enforces a minimum role level.
// Role hierarchy: viewer < operator < admin
func RequireRole(minRole model.Role) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims := ClaimsFromContext(r.Context())
			if claims == nil {
				writeError(w, http.StatusUnauthorized, "UNAUTHORIZED", "not authenticated")
				return
			}
			if !hasRole(claims.Role, minRole) {
				writeError(w, http.StatusForbidden, "FORBIDDEN", "insufficient permissions")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func hasRole(userRole, required model.Role) bool {
	order := map[model.Role]int{
		model.RoleViewer:   1,
		model.RoleOperator: 2,
		model.RoleAdmin:    3,
	}
	return order[userRole] >= order[required]
}

// ─── Rate limiter ─────────────────────────────────────────────────────────────

type ipLimiter struct {
	limiter  *rate.Limiter
	lastSeen time.Time
}

// RateLimiter provides per-IP rate limiting for sensitive endpoints (e.g. login).
type RateLimiter struct {
	mu       sync.Mutex
	limiters map[string]*ipLimiter
	r        rate.Limit // tokens per second
	b        int        // burst size
	cleanup  time.Duration
}

// NewRateLimiter creates a rate limiter. maxAttempts per windowSeconds.
func NewRateLimiter(maxAttempts, windowSeconds int) *RateLimiter {
	rl := &RateLimiter{
		limiters: make(map[string]*ipLimiter),
		r:        rate.Every(time.Duration(windowSeconds) * time.Second / time.Duration(maxAttempts)),
		b:        maxAttempts,
		cleanup:  5 * time.Minute,
	}
	go rl.cleanupLoop()
	return rl
}

// Limit returns middleware that applies this rate limiter to requests.
func (rl *RateLimiter) Limit(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := IPFromContext(r.Context())
		if !rl.allow(ip) {
			writeError(w, http.StatusTooManyRequests, "RATE_LIMITED", "too many requests, please try again later")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (rl *RateLimiter) allow(ip string) bool {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	l, exists := rl.limiters[ip]
	if !exists {
		l = &ipLimiter{limiter: rate.NewLimiter(rl.r, rl.b)}
		rl.limiters[ip] = l
	}
	l.lastSeen = time.Now()
	return l.limiter.Allow()
}

func (rl *RateLimiter) cleanupLoop() {
	for range time.Tick(rl.cleanup) {
		rl.mu.Lock()
		for ip, l := range rl.limiters {
			if time.Since(l.lastSeen) > rl.cleanup {
				delete(rl.limiters, ip)
			}
		}
		rl.mu.Unlock()
	}
}

// ─── CSRF protection ──────────────────────────────────────────────────────────

// CSRF implements the double-submit cookie pattern.
// The client must send the CSRF token as both a cookie and the X-CSRF-Token header.
// Safe methods (GET, HEAD, OPTIONS) are exempt.
func CSRF(secret string) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			// Skip safe methods
			switch r.Method {
			case http.MethodGet, http.MethodHead, http.MethodOptions:
				next.ServeHTTP(w, r)
				return
			}

			cookieToken, err := r.Cookie("csrf_token")
			if err != nil || cookieToken.Value == "" {
				writeError(w, http.StatusForbidden, "CSRF_MISSING", "CSRF token missing")
				return
			}

			headerToken := r.Header.Get("X-CSRF-Token")
			if headerToken == "" {
				writeError(w, http.StatusForbidden, "CSRF_MISSING", "X-CSRF-Token header required")
				return
			}

			// Constant-time comparison to prevent timing attacks
			if !secureEqual(cookieToken.Value, headerToken) {
				writeError(w, http.StatusForbidden, "CSRF_INVALID", "CSRF token mismatch")
				return
			}

			next.ServeHTTP(w, r)
		})
	}
}

// ─── Client IP extraction ─────────────────────────────────────────────────────

// RealIP extracts the real client IP and injects it into context.
// Trusts X-Forwarded-For only when explicitly configured for reverse proxy use.
func RealIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ip := extractIP(r)
		ctx := context.WithValue(r.Context(), ContextKeyIP, ip)
		next.ServeHTTP(w, r.WithContext(ctx))
	})
}

func extractIP(r *http.Request) string {
	// Direct connection IP
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	// Only trust X-Forwarded-For if request is from a private/loopback IP
	// (i.e., came through a trusted reverse proxy)
	ip := net.ParseIP(host)
	if ip != nil && (ip.IsLoopback() || ip.IsPrivate()) {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			if candidate := strings.TrimSpace(parts[0]); candidate != "" {
				return candidate
			}
		}
	}
	return host
}

// ─── Security headers ─────────────────────────────────────────────────────────

// SecurityHeaders sets defensive HTTP response headers.
func SecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		// Prevent MIME sniffing
		h.Set("X-Content-Type-Options", "nosniff")
		// Prevent clickjacking
		h.Set("X-Frame-Options", "DENY")
		// XSS filter (legacy browsers)
		h.Set("X-XSS-Protection", "1; mode=block")
		// Strict CSP for the panel
		h.Set("Content-Security-Policy",
			"default-src 'self'; "+
				"script-src 'self' 'unsafe-inline' 'unsafe-eval' https://cdn.jsdelivr.net https://unpkg.com; "+
				"style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "+
				"font-src 'self' https://cdn.jsdelivr.net; "+
				"img-src 'self' data:; "+
				"connect-src 'self' https://cdn.jsdelivr.net; "+
				"frame-ancestors 'none';",
		)
		// Referrer policy
		h.Set("Referrer-Policy", "strict-origin-when-cross-origin")
		// Permissions policy
		h.Set("Permissions-Policy", "geolocation=(), microphone=(), camera=()")

		next.ServeHTTP(w, r)
	})
}

// ─── Request logger ───────────────────────────────────────────────────────────

// RequestLogger logs incoming requests with timing and status.
func RequestLogger(log *zap.Logger) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			lrw := &loggingResponseWriter{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(lrw, r)

			// Don't log static asset requests to reduce noise
			if strings.HasPrefix(r.URL.Path, "/static/") {
				return
			}

			log.Info("http",
				zap.String("method", r.Method),
				zap.String("path", r.URL.Path),
				zap.Int("status", lrw.status),
				zap.Duration("duration", time.Since(start)),
				zap.String("ip", IPFromContext(r.Context())),
			)
		})
	}
}

type loggingResponseWriter struct {
	http.ResponseWriter
	status int
}

func (l *loggingResponseWriter) WriteHeader(status int) {
	l.status = status
	l.ResponseWriter.WriteHeader(status)
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func extractBearer(r *http.Request) string {
	h := r.Header.Get("Authorization")
	if strings.HasPrefix(h, "Bearer ") {
		return strings.TrimPrefix(h, "Bearer ")
	}
	return ""
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(model.APIError{Code: code, Message: message})
}

// secureEqual does a constant-time string comparison to prevent timing attacks.
func secureEqual(a, b string) bool {
	if len(a) != len(b) {
		return false
	}
	var result byte
	for i := 0; i < len(a); i++ {
		result |= a[i] ^ b[i]
	}
	return result == 0
}
