package handler

import (
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/buadamlaz/sambaguard/internal/middleware"
	"github.com/buadamlaz/sambaguard/internal/model"
	"github.com/buadamlaz/sambaguard/internal/repository"
	"github.com/buadamlaz/sambaguard/internal/service"
	"go.uber.org/zap"
)

// ─── Auth handlers ────────────────────────────────────────────────────────────

func authLogin(svc *Services, cfg interface{ IsTLS() bool }) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req model.LoginRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeAPIError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid request body")
			return
		}

		// Basic length bounds before hitting the service
		if len(req.Username) > 64 || len(req.Password) > 256 {
			writeAPIError(w, http.StatusBadRequest, "BAD_REQUEST", "input too long")
			return
		}

		ip := middleware.IPFromContext(r.Context())
		ua := r.Header.Get("User-Agent")

		pair, user, err := svc.Auth.Login(r.Context(), req.Username, req.Password, ip, ua)
		if err != nil {
			switch {
			case errors.Is(err, service.ErrInvalidCredentials):
				writeAPIError(w, http.StatusUnauthorized, "INVALID_CREDENTIALS", "invalid username or password")
			case errors.Is(err, service.ErrAccountLocked):
				writeAPIError(w, http.StatusTooManyRequests, "ACCOUNT_LOCKED", "account temporarily locked")
			case errors.Is(err, service.ErrAccountDisabled):
				writeAPIError(w, http.StatusForbidden, "ACCOUNT_DISABLED", "account is disabled")
			default:
				writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "login failed")
			}
			return
		}

		// Store refresh token in httpOnly, Secure, SameSite=Strict cookie
		secure := cfg.IsTLS()
		http.SetCookie(w, &http.Cookie{
			Name:     "refresh_token",
			Value:    pair.RefreshToken,
			HttpOnly: true,
			Secure:   secure,
			SameSite: http.SameSiteStrictMode,
			Path:     "/api/v1/auth/refresh",
			MaxAge:   7 * 24 * 3600,
		})

		// Issue CSRF token
		csrfToken, _ := generateCSRFToken()
		http.SetCookie(w, &http.Cookie{
			Name:     "csrf_token",
			Value:    csrfToken,
			HttpOnly: false, // JS must be able to read it
			Secure:   secure,
			SameSite: http.SameSiteStrictMode,
			Path:     "/",
			MaxAge:   7 * 24 * 3600,
		})

		writeJSON(w, http.StatusOK, map[string]any{
			"access_token":     pair.AccessToken,
			"expires_in":       pair.ExpiresIn,
			"must_change_pass": user.MustChangePass,
			"role":             string(user.Role),
		})
	}
}

func authRefresh(svc *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("refresh_token")
		if err != nil || cookie.Value == "" {
			writeAPIError(w, http.StatusUnauthorized, "MISSING_TOKEN", "refresh token not found")
			return
		}

		ip := middleware.IPFromContext(r.Context())
		ua := r.Header.Get("User-Agent")

		pair, _, err := svc.Auth.Refresh(r.Context(), cookie.Value, ip, ua)
		if err != nil {
			writeAPIError(w, http.StatusUnauthorized, "INVALID_TOKEN", "invalid or expired refresh token")
			return
		}

		http.SetCookie(w, &http.Cookie{
			Name:     "refresh_token",
			Value:    pair.RefreshToken,
			HttpOnly: true,
			Secure:   false, // set to true in production with TLS
			SameSite: http.SameSiteStrictMode,
			Path:     "/api/v1/auth/refresh",
			MaxAge:   7 * 24 * 3600,
		})

		writeJSON(w, http.StatusOK, map[string]any{
			"access_token": pair.AccessToken,
			"expires_in":   pair.ExpiresIn,
		})
	}
}

func authLogout(svc *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFromContext(r.Context())
		ip := middleware.IPFromContext(r.Context())

		if cookie, err := r.Cookie("refresh_token"); err == nil {
			_ = svc.Auth.Logout(r.Context(), cookie.Value, claims.UserID, claims.Username, ip)
		}

		// Clear cookies
		for _, name := range []string{"refresh_token", "csrf_token"} {
			http.SetCookie(w, &http.Cookie{
				Name:    name,
				Value:   "",
				MaxAge:  -1,
				Path:    "/",
				Expires: time.Unix(0, 0),
			})
		}

		writeJSON(w, http.StatusOK, map[string]string{"message": "logged out"})
	}
}

func authMe() http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFromContext(r.Context())
		writeJSON(w, http.StatusOK, map[string]any{
			"id":       claims.UserID,
			"username": claims.Username,
			"role":     string(claims.Role),
		})
	}
}

func issueCSRF(cfg interface{ IsTLS() bool }) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token, err := generateCSRFToken()
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", "failed to generate CSRF token")
			return
		}
		http.SetCookie(w, &http.Cookie{
			Name:     "csrf_token",
			Value:    token,
			HttpOnly: false,
			Secure:   cfg.IsTLS(),
			SameSite: http.SameSiteStrictMode,
			Path:     "/",
			MaxAge:   3600,
		})
		writeJSON(w, http.StatusOK, map[string]string{"csrf_token": token})
	}
}

// ─── Samba user handlers ──────────────────────────────────────────────────────

func listSambaUsers(svc *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		filter := &model.SambaUserFilter{
			Status: model.SambaUserStatus(q.Get("status")),
			Group:  q.Get("group"),
			Search: q.Get("search"),
			Limit:  queryInt(r, "limit", 50),
			Offset: queryInt(r, "offset", 0),
		}
		users, total, err := svc.User.List(filter)
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, model.PaginatedResponse[*model.SambaUser]{
			Items: users, Total: total,
			Limit: filter.Limit, Offset: filter.Offset,
		})
	}
}

func createSambaUser(svc *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req model.CreateSambaUserRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeAPIError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid JSON")
			return
		}

		claims := middleware.ClaimsFromContext(r.Context())
		actor := &model.PanelUser{ID: claims.UserID, Username: claims.Username, Role: claims.Role}
		ip := middleware.IPFromContext(r.Context())

		user, err := svc.User.Create(r.Context(), &req, actor, ip)
		if err != nil {
			status := http.StatusInternalServerError
			code := "INTERNAL_ERROR"
			if errors.Is(err, service.ErrUserExists) {
				status, code = http.StatusConflict, "CONFLICT"
			} else if isValidationError(err) {
				status, code = http.StatusBadRequest, "VALIDATION_ERROR"
			}
			writeAPIError(w, status, code, err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, user)
	}
}

func getSambaUser(svc *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		user, err := svc.User.GetByID(id)
		if err != nil {
			writeAPIError(w, http.StatusNotFound, "NOT_FOUND", "user not found")
			return
		}
		writeJSON(w, http.StatusOK, user)
	}
}

func updateSambaUser(svc *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		var req model.UpdateSambaUserRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeAPIError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid JSON")
			return
		}
		claims := middleware.ClaimsFromContext(r.Context())
		actor := &model.PanelUser{ID: claims.UserID, Username: claims.Username, Role: claims.Role}
		ip := middleware.IPFromContext(r.Context())

		user, err := svc.User.Update(r.Context(), id, &req, actor, ip)
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, user)
	}
}

func deleteSambaUser(svc *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		claims := middleware.ClaimsFromContext(r.Context())
		actor := &model.PanelUser{ID: claims.UserID, Username: claims.Username, Role: claims.Role}
		ip := middleware.IPFromContext(r.Context())

		if err := svc.User.Delete(r.Context(), id, actor, ip); err != nil {
			writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func changeSambaUserPassword(svc *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		var req model.ChangeSambaPasswordRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeAPIError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid JSON")
			return
		}
		claims := middleware.ClaimsFromContext(r.Context())
		actor := &model.PanelUser{ID: claims.UserID, Username: claims.Username, Role: claims.Role}
		ip := middleware.IPFromContext(r.Context())

		if err := svc.User.ChangePassword(r.Context(), id, req.NewPassword, actor, ip); err != nil {
			writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"message": "password updated"})
	}
}

// ─── Group handlers ───────────────────────────────────────────────────────────

func listGroups(svc *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		search := r.URL.Query().Get("search")
		limit := queryInt(r, "limit", 50)
		offset := queryInt(r, "offset", 0)
		groups, total, err := svc.Group.List(search, limit, offset)
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, model.PaginatedResponse[*model.SambaGroup]{
			Items: groups, Total: total, Limit: limit, Offset: offset,
		})
	}
}

func createGroup(svc *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req model.CreateGroupRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeAPIError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid JSON")
			return
		}
		claims := middleware.ClaimsFromContext(r.Context())
		actor := &model.PanelUser{ID: claims.UserID, Username: claims.Username, Role: claims.Role}
		ip := middleware.IPFromContext(r.Context())

		group, err := svc.Group.Create(r.Context(), &req, actor, ip)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, group)
	}
}

func getGroup(svc *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		group, err := svc.Group.GetByID(id)
		if err != nil {
			writeAPIError(w, http.StatusNotFound, "NOT_FOUND", "group not found")
			return
		}
		writeJSON(w, http.StatusOK, group)
	}
}

func deleteGroup(svc *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		claims := middleware.ClaimsFromContext(r.Context())
		actor := &model.PanelUser{ID: claims.UserID, Username: claims.Username, Role: claims.Role}
		ip := middleware.IPFromContext(r.Context())

		if err := svc.Group.Delete(r.Context(), id, actor, ip); err != nil {
			writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

func addGroupMember(svc *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		groupID := chi.URLParam(r, "id")
		userID := chi.URLParam(r, "userId")
		claims := middleware.ClaimsFromContext(r.Context())
		actor := &model.PanelUser{ID: claims.UserID, Username: claims.Username, Role: claims.Role}
		ip := middleware.IPFromContext(r.Context())

		if err := svc.Group.AddMember(r.Context(), groupID, userID, actor, ip); err != nil {
			writeAPIError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"message": "member added"})
	}
}

func removeGroupMember(svc *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		groupID := chi.URLParam(r, "id")
		userID := chi.URLParam(r, "userId")
		claims := middleware.ClaimsFromContext(r.Context())
		actor := &model.PanelUser{ID: claims.UserID, Username: claims.Username, Role: claims.Role}
		ip := middleware.IPFromContext(r.Context())

		if err := svc.Group.RemoveMember(r.Context(), groupID, userID, actor, ip); err != nil {
			writeAPIError(w, http.StatusBadRequest, "BAD_REQUEST", err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// ─── Share handlers ───────────────────────────────────────────────────────────

func listShares(svc *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		search := r.URL.Query().Get("search")
		limit := queryInt(r, "limit", 50)
		offset := queryInt(r, "offset", 0)
		shares, total, err := svc.Samba.ListShares(search, limit, offset)
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, model.PaginatedResponse[*model.Share]{
			Items: shares, Total: total, Limit: limit, Offset: offset,
		})
	}
}

func createShare(svc *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req model.CreateShareRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeAPIError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid JSON")
			return
		}
		claims := middleware.ClaimsFromContext(r.Context())
		actor := &model.PanelUser{ID: claims.UserID, Username: claims.Username, Role: claims.Role}
		ip := middleware.IPFromContext(r.Context())

		share, err := svc.Samba.CreateShare(r.Context(), &req, actor, ip)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, share)
	}
}

func getShare(svc *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		share, err := svc.Samba.GetShare(id)
		if err != nil {
			writeAPIError(w, http.StatusNotFound, "NOT_FOUND", "share not found")
			return
		}
		writeJSON(w, http.StatusOK, share)
	}
}

func updateShare(svc *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		var req model.UpdateShareRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeAPIError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid JSON")
			return
		}
		claims := middleware.ClaimsFromContext(r.Context())
		actor := &model.PanelUser{ID: claims.UserID, Username: claims.Username, Role: claims.Role}
		ip := middleware.IPFromContext(r.Context())

		share, err := svc.Samba.UpdateShare(r.Context(), id, &req, actor, ip)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, share)
	}
}

func deleteShare(svc *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		claims := middleware.ClaimsFromContext(r.Context())
		actor := &model.PanelUser{ID: claims.UserID, Username: claims.Username, Role: claims.Role}
		ip := middleware.IPFromContext(r.Context())

		if err := svc.Samba.DeleteShare(r.Context(), id, actor, ip); err != nil {
			writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
			return
		}
		w.WriteHeader(http.StatusNoContent)
	}
}

// ─── Config handlers ──────────────────────────────────────────────────────────

func getConfigStatus(svc *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		status, err := svc.Samba.GetConfigStatus()
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, status)
	}
}

func applyConfig(svc *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		claims := middleware.ClaimsFromContext(r.Context())
		actor := &model.PanelUser{ID: claims.UserID, Username: claims.Username, Role: claims.Role}
		ip := middleware.IPFromContext(r.Context())

		if err := svc.Samba.ApplyConfig(r.Context(), actor, ip); err != nil {
			writeAPIError(w, http.StatusInternalServerError, "APPLY_ERROR", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"message": "configuration applied and Samba restarted"})
	}
}

func backupConfig(svc *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Note string `json:"note"`
		}
		_ = json.NewDecoder(r.Body).Decode(&body)

		claims := middleware.ClaimsFromContext(r.Context())
		actor := &model.PanelUser{ID: claims.UserID, Username: claims.Username, Role: claims.Role}
		ip := middleware.IPFromContext(r.Context())

		backup, err := svc.Samba.BackupConfig(r.Context(), body.Note, actor, ip)
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "BACKUP_ERROR", err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, backup)
	}
}

func listBackups(svc *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit := queryInt(r, "limit", 20)
		offset := queryInt(r, "offset", 0)
		backups, total, err := svc.Samba.ListBackups(limit, offset)
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, model.PaginatedResponse[*model.ConfigBackup]{
			Items: backups, Total: total, Limit: limit, Offset: offset,
		})
	}
}

func listVersions(svc *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		limit := queryInt(r, "limit", 20)
		offset := queryInt(r, "offset", 0)
		versions, total, err := svc.Samba.ListVersions(limit, offset)
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, model.PaginatedResponse[*model.ConfigVersion]{
			Items: versions, Total: total, Limit: limit, Offset: offset,
		})
	}
}

func getVersionContent(svc *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		content, err := svc.Samba.GetVersionContent(id)
		if err != nil {
			writeAPIError(w, http.StatusNotFound, "NOT_FOUND", "version not found")
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"content": content})
	}
}

// ─── Audit log handlers ───────────────────────────────────────────────────────

func listAuditLogs(svc *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		q := r.URL.Query()
		filter := &model.AuditLogFilter{
			ActorID:    q.Get("actor_id"),
			Action:     model.AuditAction(q.Get("action")),
			TargetType: q.Get("target_type"),
			Search:     q.Get("search"),
			Limit:      queryInt(r, "limit", 50),
			Offset:     queryInt(r, "offset", 0),
		}
		entries, total, err := svc.AuditRepo.List(filter)
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, model.PaginatedResponse[*model.AuditLog]{
			Items: entries, Total: total,
			Limit: filter.Limit, Offset: filter.Offset,
		})
	}
}

func getStats(svc *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		stats, err := svc.AuditRepo.Stats()
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, stats)
	}
}

// ─── Panel user handlers ──────────────────────────────────────────────────────

func listPanelUsers(svc *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		filter := &model.PanelUserFilter{
			Search: r.URL.Query().Get("search"),
			Limit:  queryInt(r, "limit", 50),
			Offset: queryInt(r, "offset", 0),
		}
		users, total, err := svc.PanelUser.ListPanelUsers(filter)
		if err != nil {
			writeAPIError(w, http.StatusInternalServerError, "INTERNAL_ERROR", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, model.PaginatedResponse[*model.PanelUser]{
			Items: users, Total: total,
			Limit: filter.Limit, Offset: filter.Offset,
		})
	}
}

func createPanelUser(svc *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Username string     `json:"username"`
			Password string     `json:"password"`
			Email    string     `json:"email"`
			Role     model.Role `json:"role"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeAPIError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid JSON")
			return
		}

		claims := middleware.ClaimsFromContext(r.Context())
		actor := &model.PanelUser{ID: claims.UserID, Username: claims.Username, Role: claims.Role}
		ip := middleware.IPFromContext(r.Context())

		user, err := svc.PanelUser.CreatePanelUser(r.Context(), req.Username, req.Password, req.Email, req.Role, actor, ip)
		if err != nil {
			writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
			return
		}
		writeJSON(w, http.StatusCreated, user)
	}
}

func changePanelUserPassword(svc *Services) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := chi.URLParam(r, "id")
		var req struct {
			NewPassword string `json:"new_password"`
		}
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			writeAPIError(w, http.StatusBadRequest, "BAD_REQUEST", "invalid JSON")
			return
		}
		claims := middleware.ClaimsFromContext(r.Context())
		actor := &model.PanelUser{ID: claims.UserID, Username: claims.Username, Role: claims.Role}
		ip := middleware.IPFromContext(r.Context())

		if err := svc.PanelUser.ChangePanelUserPassword(r.Context(), id, req.NewPassword, actor, ip); err != nil {
			writeAPIError(w, http.StatusBadRequest, "VALIDATION_ERROR", err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"message": "password updated"})
	}
}

// ─── SSE handler ──────────────────────────────────────────────────────────────

// sseEvents streams real-time notifications to the client.
func sseEvents(log *zap.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming not supported", http.StatusInternalServerError)
			return
		}

		w.Header().Set("Content-Type", "text/event-stream")
		w.Header().Set("Cache-Control", "no-cache")
		w.Header().Set("Connection", "keep-alive")
		w.Header().Set("X-Accel-Buffering", "no") // Disable nginx buffering

		// Send initial ping
		fmt.Fprintf(w, "event: ping\ndata: {\"time\":\"%s\"}\n\n", time.Now().UTC().Format(time.RFC3339))
		flusher.Flush()

		// Keep connection alive with periodic pings
		ticker := time.NewTicker(30 * time.Second)
		defer ticker.Stop()

		for {
			select {
			case <-r.Context().Done():
				return
			case t := <-ticker.C:
				fmt.Fprintf(w, "event: ping\ndata: {\"time\":\"%s\"}\n\n", t.UTC().Format(time.RFC3339))
				flusher.Flush()
			}
		}
	}
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

func generateCSRFToken() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b), nil
}

func isValidationError(err error) bool {
	// Errors from validation return specific messages — not wrapping ErrX for now
	// In a larger codebase, use a sentinel or typed error
	return err != nil && (
		errors.Is(err, service.ErrUserExists) ||
		errors.Is(err, service.ErrUserNotFound))
}

// compile-time interface checks
var (
	_ = repository.ErrNotFound
	_ = service.ErrMustChangePassword
)
