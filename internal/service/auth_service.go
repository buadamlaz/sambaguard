// Package service implements business logic, orchestrating repositories and
// system packages. Services are the only layer that calls pkg/system and
// pkg/samba — handlers must never bypass them.
package service

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/buadamlaz/sambaguard/internal/config"
	"github.com/buadamlaz/sambaguard/internal/model"
	"github.com/buadamlaz/sambaguard/internal/repository"
	"go.uber.org/zap"
	"golang.org/x/crypto/bcrypt"
)

// ─── Sentinel errors ──────────────────────────────────────────────────────────

var (
	ErrInvalidCredentials = errors.New("invalid username or password")
	ErrAccountLocked      = errors.New("account temporarily locked due to too many failed attempts")
	ErrAccountDisabled    = errors.New("account is disabled")
	ErrInvalidToken       = errors.New("invalid or expired token")
	ErrMustChangePassword = errors.New("password change required before proceeding")
)

// AuthService handles authentication and session management.
type AuthService struct {
	cfg          *config.Config
	panelUsers   *repository.PanelUserRepo
	refreshTokens *repository.RefreshTokenRepo
	audit        *repository.AuditRepo
	log          *zap.Logger
}

func NewAuthService(
	cfg *config.Config,
	panelUsers *repository.PanelUserRepo,
	refreshTokens *repository.RefreshTokenRepo,
	audit *repository.AuditRepo,
	log *zap.Logger,
) *AuthService {
	return &AuthService{
		cfg:           cfg,
		panelUsers:    panelUsers,
		refreshTokens: refreshTokens,
		audit:         audit,
		log:           log,
	}
}

// Login authenticates a panel user and returns a token pair on success.
// It enforces lockout after repeated failures to resist brute-force attacks.
func (s *AuthService) Login(ctx context.Context, username, password, ip, ua string) (*model.TokenPair, *model.PanelUser, error) {
	user, err := s.panelUsers.GetByUsername(username)
	if err != nil {
		// Always do the bcrypt work to prevent timing-based user enumeration
		_ = bcrypt.CompareHashAndPassword([]byte("$2a$12$dummy.hash.to.prevent.timing.attacks"), []byte(password))
		s.writeAudit(ctx, "", username, model.ActionLoginFailed, "panel_user", "", username,
			`{"reason":"user_not_found"}`, ip, false, "user not found")
		return nil, nil, ErrInvalidCredentials
	}

	// Check account lockout
	if user.LockedUntil != nil && time.Now().Before(*user.LockedUntil) {
		s.writeAudit(ctx, user.ID, username, model.ActionLoginFailed, "panel_user", user.ID, username,
			`{"reason":"account_locked"}`, ip, false, "account locked")
		return nil, nil, ErrAccountLocked
	}

	// Check disabled
	if user.Disabled {
		_ = bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password))
		s.writeAudit(ctx, user.ID, username, model.ActionLoginFailed, "panel_user", user.ID, username,
			`{"reason":"account_disabled"}`, ip, false, "account disabled")
		return nil, nil, ErrAccountDisabled
	}

	// Verify password (bcrypt — constant-time)
	if err := bcrypt.CompareHashAndPassword([]byte(user.PasswordHash), []byte(password)); err != nil {
		user.FailedLoginCount++
		// Lockout after N failures
		if user.FailedLoginCount >= s.cfg.RateLimitLogin {
			lockUntil := time.Now().Add(time.Duration(s.cfg.RateLimitWindowSec) * time.Second)
			user.LockedUntil = &lockUntil
			user.FailedLoginCount = 0
			s.log.Warn("account locked after failed attempts",
				zap.String("username", username),
				zap.String("ip", ip),
			)
		}
		_ = s.panelUsers.Update(user)
		s.writeAudit(ctx, user.ID, username, model.ActionLoginFailed, "panel_user", user.ID, username,
			fmt.Sprintf(`{"reason":"bad_password","failed_count":%d}`, user.FailedLoginCount), ip, false, "bad password")
		return nil, nil, ErrInvalidCredentials
	}

	// Success — reset failure counter
	user.FailedLoginCount = 0
	user.LockedUntil = nil
	now := time.Now()
	user.LastLoginAt = &now
	_ = s.panelUsers.Update(user)

	// Issue tokens
	pair, err := s.issueTokenPair(user, ip, ua)
	if err != nil {
		return nil, nil, fmt.Errorf("issue tokens: %w", err)
	}

	s.writeAudit(ctx, user.ID, username, model.ActionLogin, "panel_user", user.ID, username,
		`{}`, ip, true, "")

	return pair, user, nil
}

// Refresh validates a refresh token and issues a new token pair (rotation).
func (s *AuthService) Refresh(ctx context.Context, refreshToken, ip, ua string) (*model.TokenPair, *model.PanelUser, error) {
	// Validate JWT signature
	claims, err := s.parseToken(refreshToken, "refresh")
	if err != nil {
		return nil, nil, ErrInvalidToken
	}

	// Check server-side storage (allows revocation)
	hash := hashToken(refreshToken)
	userID, valid, err := s.refreshTokens.Verify(hash)
	if err != nil || !valid || userID != claims.UserID {
		return nil, nil, ErrInvalidToken
	}

	// Revoke the used token (rotation — each refresh token is single-use)
	if err := s.refreshTokens.Revoke(hash); err != nil {
		s.log.Error("failed to revoke refresh token", zap.Error(err))
	}

	user, err := s.panelUsers.GetByID(userID)
	if err != nil {
		return nil, nil, ErrInvalidToken
	}
	if user.Disabled {
		return nil, nil, ErrAccountDisabled
	}

	pair, err := s.issueTokenPair(user, ip, ua)
	if err != nil {
		return nil, nil, fmt.Errorf("issue tokens: %w", err)
	}
	return pair, user, nil
}

// Logout revokes the given refresh token.
func (s *AuthService) Logout(ctx context.Context, refreshToken, actorID, actorName, ip string) error {
	hash := hashToken(refreshToken)
	_ = s.refreshTokens.Revoke(hash)
	s.writeAudit(ctx, actorID, actorName, model.ActionLogout, "panel_user", actorID, actorName,
		`{}`, ip, true, "")
	return nil
}

// ValidateAccessToken parses and validates a JWT access token.
func (s *AuthService) ValidateAccessToken(tokenStr string) (*model.Claims, error) {
	return s.parseToken(tokenStr, "access")
}

// HashPassword hashes a plaintext password with bcrypt.
func (s *AuthService) HashPassword(password string) (string, error) {
	hash, err := bcrypt.GenerateFromPassword([]byte(password), s.cfg.BCryptCost)
	if err != nil {
		return "", fmt.Errorf("bcrypt: %w", err)
	}
	return string(hash), nil
}

// GenerateRandomPassword generates a cryptographically secure random password.
func GenerateRandomPassword(length int) (string, error) {
	b := make([]byte, length)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(b)[:length], nil
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

func (s *AuthService) issueTokenPair(user *model.PanelUser, ip, ua string) (*model.TokenPair, error) {
	accessExpiry := time.Duration(s.cfg.JWTAccessExpiry) * time.Minute
	refreshExpiry := time.Duration(s.cfg.JWTRefreshExpiry) * time.Hour

	accessToken, err := s.signToken(user, "access", accessExpiry)
	if err != nil {
		return nil, err
	}

	refreshToken, err := s.signToken(user, "refresh", refreshExpiry)
	if err != nil {
		return nil, err
	}

	// Store refresh token hash server-side (enables revocation)
	tokenID := uuid.New().String()
	hash := hashToken(refreshToken)
	if err := s.refreshTokens.Store(tokenID, user.ID, hash, time.Now().Add(refreshExpiry), ip, ua); err != nil {
		return nil, fmt.Errorf("store refresh token: %w", err)
	}

	return &model.TokenPair{
		AccessToken:  accessToken,
		RefreshToken: refreshToken,
		ExpiresIn:    int(accessExpiry.Seconds()),
	}, nil
}

func (s *AuthService) signToken(user *model.PanelUser, tokenType string, expiry time.Duration) (string, error) {
	now := time.Now()
	claims := jwt.MapClaims{
		"uid":  user.ID,
		"usr":  user.Username,
		"role": string(user.Role),
		"typ":  tokenType,
		"iat":  now.Unix(),
		"exp":  now.Add(expiry).Unix(),
		"jti":  uuid.New().String(), // unique token ID
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString([]byte(s.cfg.JWTSecret))
}

func (s *AuthService) parseToken(tokenStr, expectedType string) (*model.Claims, error) {
	token, err := jwt.Parse(tokenStr, func(t *jwt.Token) (any, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(s.cfg.JWTSecret), nil
	})
	if err != nil || !token.Valid {
		return nil, ErrInvalidToken
	}

	mc, ok := token.Claims.(jwt.MapClaims)
	if !ok {
		return nil, ErrInvalidToken
	}

	typ, _ := mc["typ"].(string)
	if typ != expectedType {
		return nil, ErrInvalidToken
	}

	return &model.Claims{
		UserID:    mc["uid"].(string),
		Username:  mc["usr"].(string),
		Role:      model.Role(mc["role"].(string)),
		TokenType: typ,
	}, nil
}

// hashToken returns the SHA-256 hex digest of a token string.
// We store hashes, not raw tokens, so a DB breach can't replay refresh tokens.
func hashToken(token string) string {
	h := sha256.Sum256([]byte(token))
	return hex.EncodeToString(h[:])
}

func (s *AuthService) writeAudit(ctx context.Context, actorID, actorName string, action model.AuditAction,
	targetType, targetID, targetName, details, ip string, success bool, errMsg string) {
	entry := &model.AuditLog{
		ID:         uuid.New().String(),
		Timestamp:  time.Now().UTC(),
		ActorID:    actorID,
		ActorName:  actorName,
		Action:     action,
		TargetType: targetType,
		TargetID:   targetID,
		TargetName: targetName,
		Details:    details,
		IPAddress:  ip,
		Success:    success,
		ErrorMsg:   errMsg,
	}
	if err := s.audit.Append(entry); err != nil {
		s.log.Error("audit write failed", zap.Error(err))
	}
}
