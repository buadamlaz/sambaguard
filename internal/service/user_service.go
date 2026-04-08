package service

import (
	"context"
	"errors"
	"fmt"
	"regexp"
	"time"
	"unicode/utf8"

	"github.com/google/uuid"
	"github.com/buadamlaz/sambaguard/internal/model"
	"github.com/buadamlaz/sambaguard/internal/repository"
	"github.com/buadamlaz/sambaguard/pkg/system"
	"go.uber.org/zap"
)

var (
	reValidUsername = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,30}$`)
	ErrUserExists   = errors.New("user already exists")
	ErrUserNotFound = errors.New("user not found")
)

// UserService manages Samba users.
type UserService struct {
	users     *repository.SambaUserRepo
	groups    *repository.SambaGroupRepo
	configState *repository.ConfigStateRepo
	sysUser   *system.UserManager
	audit     *repository.AuditRepo
	log       *zap.Logger
}

func NewUserService(
	users *repository.SambaUserRepo,
	groups *repository.SambaGroupRepo,
	configState *repository.ConfigStateRepo,
	sysUser *system.UserManager,
	audit *repository.AuditRepo,
	log *zap.Logger,
) *UserService {
	return &UserService{
		users:       users,
		groups:      groups,
		configState: configState,
		sysUser:     sysUser,
		audit:       audit,
		log:         log,
	}
}

// Create creates a new Samba user: DB record + OS account + Samba password.
// It is transactional in spirit: if any step fails, previously completed steps
// are rolled back where possible.
func (s *UserService) Create(ctx context.Context, req *model.CreateSambaUserRequest, actor *model.PanelUser, ip string) (*model.SambaUser, error) {
	// ── Validate input ────────────────────────────────────────────────────
	if err := validateSambaUsername(req.Username); err != nil {
		return nil, err
	}
	if err := validateSambaPassword(req.Password); err != nil {
		return nil, err
	}
	if len(req.DisplayName) > 128 {
		return nil, errors.New("display_name too long (max 128)")
	}

	// ── Check uniqueness ──────────────────────────────────────────────────
	if _, err := s.users.GetByUsername(req.Username); err == nil {
		return nil, ErrUserExists
	}

	user := &model.SambaUser{
		ID:          uuid.New().String(),
		Username:    req.Username,
		DisplayName: req.DisplayName,
		Status:      model.SambaUserEnabled,
		Comment:     req.Comment,
		CreatedAt:   time.Now().UTC(),
		UpdatedAt:   time.Now().UTC(),
		CreatedBy:   actor.ID,
	}

	// ── OS operations (no shell, no home, no SSH) ─────────────────────────
	if err := s.sysUser.CreateSambaUser(req.Username); err != nil {
		return nil, fmt.Errorf("create OS user: %w", err)
	}
	s.log.Info("created OS user", zap.String("username", req.Username))

	if err := s.sysUser.SetSambaPassword(req.Username, req.Password); err != nil {
		// Rollback OS user creation
		_ = s.sysUser.DeleteSambaUser(req.Username)
		return nil, fmt.Errorf("set Samba password: %w", err)
	}

	// ── Persist to DB ─────────────────────────────────────────────────────
	if err := s.users.Create(user); err != nil {
		// Rollback OS operations
		_ = s.sysUser.DeleteSambaUser(req.Username)
		return nil, fmt.Errorf("persist user: %w", err)
	}

	// ── Add to groups ─────────────────────────────────────────────────────
	for _, groupName := range req.Groups {
		group, err := s.groups.GetByName(groupName)
		if err != nil {
			s.log.Warn("group not found during user creation", zap.String("group", groupName))
			continue
		}
		if err := s.sysUser.AddUserToGroup(req.Username, groupName); err != nil {
			s.log.Warn("failed to add user to OS group",
				zap.String("user", req.Username),
				zap.String("group", groupName),
				zap.Error(err),
			)
		}
		if err := s.groups.AddMember(group.ID, user.ID, actor.ID); err != nil {
			s.log.Warn("failed to add user to DB group", zap.Error(err))
		}
	}

	// ── Config change pending ──────────────────────────────────────────────
	_ = s.configState.MarkPending()

	// ── Audit ─────────────────────────────────────────────────────────────
	s.writeAudit(actor, model.ActionUserCreate, "samba_user", user.ID, req.Username,
		fmt.Sprintf(`{"display_name":%q,"groups":%q}`, req.DisplayName, req.Groups), ip, true, "")

	groups, _ := s.users.GetUserGroups(user.ID)
	user.Groups = groups
	return user, nil
}

// Update updates a Samba user's metadata (not password).
func (s *UserService) Update(ctx context.Context, userID string, req *model.UpdateSambaUserRequest, actor *model.PanelUser, ip string) (*model.SambaUser, error) {
	user, err := s.users.GetByID(userID)
	if err != nil {
		return nil, ErrUserNotFound
	}

	oldStatus := user.Status
	user.DisplayName = req.DisplayName
	user.Comment = req.Comment

	if req.Status != "" && req.Status != user.Status {
		switch req.Status {
		case model.SambaUserEnabled:
			if err := s.sysUser.EnableSambaUser(user.Username); err != nil {
				return nil, fmt.Errorf("enable Samba user: %w", err)
			}
		case model.SambaUserDisabled:
			if err := s.sysUser.DisableSambaUser(user.Username); err != nil {
				return nil, fmt.Errorf("disable Samba user: %w", err)
			}
		default:
			return nil, fmt.Errorf("invalid status: %s", req.Status)
		}
		user.Status = req.Status
	}

	if err := s.users.Update(user); err != nil {
		return nil, fmt.Errorf("update user: %w", err)
	}

	action := model.ActionUserUpdate
	if req.Status == model.SambaUserEnabled && oldStatus != req.Status {
		action = model.ActionUserEnable
	} else if req.Status == model.SambaUserDisabled && oldStatus != req.Status {
		action = model.ActionUserDisable
	}

	s.writeAudit(actor, action, "samba_user", userID, user.Username,
		fmt.Sprintf(`{"status":%q}`, user.Status), ip, true, "")

	return user, nil
}

// ChangePassword changes a Samba user's password.
func (s *UserService) ChangePassword(ctx context.Context, userID, newPassword string, actor *model.PanelUser, ip string) error {
	user, err := s.users.GetByID(userID)
	if err != nil {
		return ErrUserNotFound
	}

	if err := validateSambaPassword(newPassword); err != nil {
		return err
	}

	if err := s.sysUser.SetSambaPassword(user.Username, newPassword); err != nil {
		return fmt.Errorf("set Samba password: %w", err)
	}

	s.writeAudit(actor, model.ActionUserPassChange, "samba_user", userID, user.Username,
		`{}`, ip, true, "")
	return nil
}

// Delete removes a Samba user from the OS and database.
func (s *UserService) Delete(ctx context.Context, userID string, actor *model.PanelUser, ip string) error {
	user, err := s.users.GetByID(userID)
	if err != nil {
		return ErrUserNotFound
	}

	// OS removal
	if err := s.sysUser.DeleteSambaUser(user.Username); err != nil {
		return fmt.Errorf("delete OS user: %w", err)
	}

	// DB removal (cascades to group_members)
	if err := s.users.Delete(userID); err != nil {
		return fmt.Errorf("delete DB record: %w", err)
	}

	_ = s.configState.MarkPending()

	s.writeAudit(actor, model.ActionUserDelete, "samba_user", userID, user.Username,
		`{}`, ip, true, "")
	return nil
}

// GetByID returns a Samba user by ID.
func (s *UserService) GetByID(id string) (*model.SambaUser, error) {
	return s.users.GetByID(id)
}

// List returns a filtered, paginated list of Samba users.
func (s *UserService) List(f *model.SambaUserFilter) ([]*model.SambaUser, int64, error) {
	return s.users.List(f)
}

// ─── Panel user management (RBAC-protected at handler level) ──────────────────

// PanelUserService manages web panel accounts.
type PanelUserService struct {
	panelUsers *repository.PanelUserRepo
	auth       *AuthService
	audit      *repository.AuditRepo
	log        *zap.Logger
}

func NewPanelUserService(
	panelUsers *repository.PanelUserRepo,
	auth *AuthService,
	audit *repository.AuditRepo,
	log *zap.Logger,
) *PanelUserService {
	return &PanelUserService{
		panelUsers: panelUsers,
		auth:       auth,
		audit:      audit,
		log:        log,
	}
}

// EnsureBootstrapAdmin creates the initial admin account if no panel users exist.
func (s *PanelUserService) EnsureBootstrapAdmin(username, password string) error {
	count, err := s.panelUsers.Count()
	if err != nil {
		return err
	}
	if count > 0 {
		return nil // already bootstrapped
	}

	if password == "" {
		var err error
		password, err = GenerateRandomPassword(20)
		if err != nil {
			return err
		}
		s.log.Warn("═══════════════════════════════════════════════════════════")
		s.log.Warn("FIRST RUN: generated admin credentials")
		s.log.Warn("  Username: " + username)
		s.log.Warn("  Password: " + password)
		s.log.Warn("  CHANGE THIS PASSWORD IMMEDIATELY AFTER FIRST LOGIN")
		s.log.Warn("═══════════════════════════════════════════════════════════")
	}

	hash, err := s.auth.HashPassword(password)
	if err != nil {
		return err
	}

	now := time.Now().UTC()
	u := &model.PanelUser{
		ID:           uuid.New().String(),
		Username:     username,
		PasswordHash: hash,
		Role:         model.RoleAdmin,
		MustChangePass: true,
		CreatedAt:    now,
		UpdatedAt:    now,
	}
	return s.panelUsers.Create(u)
}

// CreatePanelUser creates a new panel user (admin only).
func (s *PanelUserService) CreatePanelUser(ctx context.Context, username, password, email string, role model.Role, actor *model.PanelUser, ip string) (*model.PanelUser, error) {
	if !reValidUsername.MatchString(username) {
		return nil, errors.New("invalid username format")
	}
	if len(password) < 12 {
		return nil, errors.New("panel user password must be at least 12 characters")
	}

	hash, err := s.auth.HashPassword(password)
	if err != nil {
		return nil, err
	}

	now := time.Now().UTC()
	u := &model.PanelUser{
		ID:           uuid.New().String(),
		Username:     username,
		PasswordHash: hash,
		Role:         role,
		Email:        email,
		MustChangePass: false,
		CreatedAt:    now,
		UpdatedAt:    now,
	}

	if err := s.panelUsers.Create(u); err != nil {
		return nil, err
	}

	s.writeAudit(actor, model.ActionPanelUserCreate, "panel_user", u.ID, username,
		fmt.Sprintf(`{"role":%q}`, role), ip, true, "")
	return u, nil
}

// ChangePanelUserPassword updates a panel user's password.
func (s *PanelUserService) ChangePanelUserPassword(ctx context.Context, userID, newPassword string, actor *model.PanelUser, ip string) error {
	if len(newPassword) < 12 {
		return errors.New("password must be at least 12 characters")
	}

	user, err := s.panelUsers.GetByID(userID)
	if err != nil {
		return ErrUserNotFound
	}

	hash, err := s.auth.HashPassword(newPassword)
	if err != nil {
		return err
	}

	user.PasswordHash = hash
	user.MustChangePass = false
	return s.panelUsers.Update(user)
}

// ListPanelUsers returns a paginated list of panel users.
func (s *PanelUserService) ListPanelUsers(f *model.PanelUserFilter) ([]*model.PanelUser, int64, error) {
	return s.panelUsers.List(f)
}

// ─── Validation ───────────────────────────────────────────────────────────────

func validateSambaUsername(u string) error {
	if !reValidUsername.MatchString(u) {
		return fmt.Errorf("invalid Samba username %q: must match ^[a-z_][a-z0-9_-]{0,30}$", u)
	}
	return nil
}

func validateSambaPassword(p string) error {
	if !utf8.ValidString(p) {
		return errors.New("password contains invalid UTF-8 sequences")
	}
	if len(p) < 8 || len(p) > 128 {
		return errors.New("Samba password must be 8-128 characters")
	}
	return nil
}

// ─── Audit helper ─────────────────────────────────────────────────────────────

func (s *UserService) writeAudit(actor *model.PanelUser, action model.AuditAction,
	targetType, targetID, targetName, details, ip string, success bool, errMsg string) {
	entry := &model.AuditLog{
		ID:         uuid.New().String(),
		Timestamp:  time.Now().UTC(),
		ActorID:    actor.ID,
		ActorName:  actor.Username,
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

func (s *PanelUserService) writeAudit(actor *model.PanelUser, action model.AuditAction,
	targetType, targetID, targetName, details, ip string, success bool, errMsg string) {
	entry := &model.AuditLog{
		ID:         uuid.New().String(),
		Timestamp:  time.Now().UTC(),
		ActorID:    actor.ID,
		ActorName:  actor.Username,
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
