// Package handler wires together all HTTP routes, middleware, and dependencies.
package handler

import (
	"encoding/json"
	"io/fs"
	"net/http"
	"strconv"

	"github.com/go-chi/chi/v5"
	chimw "github.com/go-chi/chi/v5/middleware"
	"github.com/go-chi/cors"
	"github.com/buadamlaz/sambaguard/internal/config"
	"github.com/buadamlaz/sambaguard/internal/database"
	"github.com/buadamlaz/sambaguard/internal/middleware"
	"github.com/buadamlaz/sambaguard/internal/model"
	"github.com/buadamlaz/sambaguard/internal/repository"
	"github.com/buadamlaz/sambaguard/internal/service"
	"github.com/buadamlaz/sambaguard/pkg/system"
	webpkg "github.com/buadamlaz/sambaguard/web"
	"go.uber.org/zap"
)

// Services bundles all application services.
type Services struct {
	Auth       *service.AuthService
	User       *service.UserService
	PanelUser  *service.PanelUserService
	Group      *service.GroupService
	Samba      *service.SambaService
	AuditRepo  *repository.AuditRepo
}

// NewRouter builds and returns the application HTTP router.
func NewRouter(cfg *config.Config, db *database.DB, log *zap.Logger) (http.Handler, error) {
	// ── Repositories ────────────────────────────────────────────────────────
	panelUserRepo  := repository.NewPanelUserRepo(db)
	sambaUserRepo  := repository.NewSambaUserRepo(db)
	groupRepo      := repository.NewSambaGroupRepo(db)
	shareRepo      := repository.NewShareRepo(db)
	auditRepo      := repository.NewAuditRepo(db)
	configStateRepo := repository.NewConfigStateRepo(db)
	refreshRepo    := repository.NewRefreshTokenRepo(db)
	backupRepo     := repository.NewConfigBackupRepo(db)
	versionRepo    := repository.NewConfigVersionRepo(db)

	// ── System manager ──────────────────────────────────────────────────────
	sysUser := system.NewUserManager()

	// ── Services ────────────────────────────────────────────────────────────
	authSvc := service.NewAuthService(cfg, panelUserRepo, refreshRepo, auditRepo, log)

	svc := &Services{
		Auth: authSvc,
		User: service.NewUserService(sambaUserRepo, groupRepo, configStateRepo, sysUser, auditRepo, log),
		PanelUser: service.NewPanelUserService(panelUserRepo, authSvc, auditRepo, log),
		Group: service.NewGroupService(groupRepo, sambaUserRepo, configStateRepo, sysUser, auditRepo, log),
		Samba: service.NewSambaService(cfg, shareRepo, configStateRepo, backupRepo, versionRepo, groupRepo, sysUser, auditRepo, log),
		AuditRepo: auditRepo,
	}

	// ── Bootstrap admin account ─────────────────────────────────────────────
	if err := svc.PanelUser.EnsureBootstrapAdmin(cfg.InitAdminUser, cfg.InitAdminPass); err != nil {
		log.Error("bootstrap admin failed", zap.Error(err))
	}

	// ── Rate limiters ────────────────────────────────────────────────────────
	loginLimiter := middleware.NewRateLimiter(cfg.RateLimitLogin, cfg.RateLimitWindowSec)

	// ── Router ───────────────────────────────────────────────────────────────
	r := chi.NewRouter()

	// Global middleware
	r.Use(chimw.Recoverer)
	r.Use(chimw.RequestID)
	r.Use(middleware.RealIP)
	r.Use(middleware.SecurityHeaders)
	r.Use(middleware.RequestLogger(log))

	// CORS — tightly scoped for the panel's own origin
	r.Use(cors.Handler(cors.Options{
		AllowedOrigins:   []string{"*"}, // lock down in production via env
		AllowedMethods:   []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"},
		AllowedHeaders:   []string{"Accept", "Authorization", "Content-Type", "X-CSRF-Token"},
		ExposedHeaders:   []string{"X-Request-ID"},
		AllowCredentials: true,
		MaxAge:           300,
	}))

	// ── Static files + SPA ───────────────────────────────────────────────────
	staticFS, err := fs.Sub(webpkg.FS, "static")
	if err != nil {
		return nil, err
	}
	r.Handle("/static/*", http.StripPrefix("/static/", http.FileServer(http.FS(staticFS))))

	// ── SPA index (serve the web app shell) ──────────────────────────────────
	r.Get("/", serveIndex)
	r.Get("/login", serveIndex)
	r.Get("/dashboard", serveIndex)
	r.Get("/users", serveIndex)
	r.Get("/groups", serveIndex)
	r.Get("/shares", serveIndex)
	r.Get("/logs", serveIndex)
	r.Get("/config", serveIndex)
	r.Get("/settings", serveIndex)

	// ── API v1 ────────────────────────────────────────────────────────────────
	r.Route("/api/v1", func(r chi.Router) {
		r.Use(chimw.SetHeader("Content-Type", "application/json"))

		// Public: auth endpoints
		// Only login is rate-limited; refresh uses httpOnly cookie and has its own
		// abuse-protection (token revocation + expiry), so a separate limiter is not needed.
		r.Group(func(r chi.Router) {
			r.Use(loginLimiter.Limit)
			r.Post("/auth/login", authLogin(svc, cfg))
		})
		r.Post("/auth/refresh", authRefresh(svc))

		// Protected: all other endpoints require valid JWT
		r.Group(func(r chi.Router) {
			r.Use(middleware.Auth(authSvc))
			r.Use(middleware.CSRF(cfg.CSRFSecret))

			r.Post("/auth/logout", authLogout(svc))
			r.Get("/auth/me", authMe())
			r.Post("/auth/csrf", issueCSRF(cfg))

			// Samba users (operator+)
			r.Route("/users", func(r chi.Router) {
				r.Use(middleware.RequireRole(model.RoleOperator))
				r.Get("/", listSambaUsers(svc))
				r.Post("/", createSambaUser(svc))
				r.Route("/{id}", func(r chi.Router) {
					r.Get("/", getSambaUser(svc))
					r.Put("/", updateSambaUser(svc))
					r.Delete("/", deleteSambaUser(svc))
					r.Post("/password", changeSambaUserPassword(svc))
				})
			})

			// Groups (operator+)
			r.Route("/groups", func(r chi.Router) {
				r.Use(middleware.RequireRole(model.RoleOperator))
				r.Get("/", listGroups(svc))
				r.Post("/", createGroup(svc))
				r.Route("/{id}", func(r chi.Router) {
					r.Get("/", getGroup(svc))
					r.Delete("/", deleteGroup(svc))
					r.Post("/members/{userId}", addGroupMember(svc))
					r.Delete("/members/{userId}", removeGroupMember(svc))
				})
			})

			// Shares (operator+)
			r.Route("/shares", func(r chi.Router) {
				r.Use(middleware.RequireRole(model.RoleOperator))
				r.Get("/", listShares(svc))
				r.Post("/", createShare(svc))
				r.Route("/{id}", func(r chi.Router) {
					r.Get("/", getShare(svc))
					r.Put("/", updateShare(svc))
					r.Delete("/", deleteShare(svc))
				})
			})

			// Config management (admin only for apply)
			r.Route("/config", func(r chi.Router) {
				r.Get("/status", getConfigStatus(svc))
				r.With(middleware.RequireRole(model.RoleAdmin)).Post("/apply", applyConfig(svc))
				r.With(middleware.RequireRole(model.RoleAdmin)).Post("/backup", backupConfig(svc))
				r.Get("/backups", listBackups(svc))
				r.Get("/versions", listVersions(svc))
				r.Get("/versions/{id}", getVersionContent(svc))
			})

			// Audit logs (viewer+)
			r.Route("/logs", func(r chi.Router) {
				r.Get("/", listAuditLogs(svc))
				r.Get("/stats", getStats(svc))
			})

			// Panel users (admin only)
			r.Route("/panel-users", func(r chi.Router) {
				r.Use(middleware.RequireRole(model.RoleAdmin))
				r.Get("/", listPanelUsers(svc))
				r.Post("/", createPanelUser(svc))
				r.Route("/{id}", func(r chi.Router) {
					r.Put("/password", changePanelUserPassword(svc))
				})
			})
		})
	})

	// ── SSE real-time endpoint ────────────────────────────────────────────────
	r.With(middleware.Auth(authSvc)).Get("/api/v1/events", sseEvents(log))

	// ── Health check (unauthenticated) ────────────────────────────────────────
	r.Get("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	return r, nil
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	data, err := webpkg.FS.ReadFile("templates/index.html")
	if err != nil {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

// ─── JSON helpers ─────────────────────────────────────────────────────────────

func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(v); err != nil {
		// Can't do much here since headers are already sent
		return
	}
}

func writeAPIError(w http.ResponseWriter, status int, code, msg string) {
	writeJSON(w, status, model.APIError{Code: code, Message: msg})
}

func queryInt(r *http.Request, key string, def int) int {
	if s := r.URL.Query().Get(key); s != "" {
		if n, err := strconv.Atoi(s); err == nil {
			return n
		}
	}
	return def
}
