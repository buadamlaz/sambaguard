package service

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/buadamlaz/sambaguard/internal/config"
	"github.com/buadamlaz/sambaguard/internal/model"
	"github.com/buadamlaz/sambaguard/internal/repository"
	"github.com/buadamlaz/sambaguard/pkg/samba"
	"github.com/buadamlaz/sambaguard/pkg/system"
	"go.uber.org/zap"
)

var (
	reShareName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9 _-]{0,79}$`)
	reAbsPath   = regexp.MustCompile(`^/[a-zA-Z0-9/_.-]*$`)
	reOctalMode = regexp.MustCompile(`^0[0-7]{3}$`)
)

// SambaService orchestrates share management and smb.conf lifecycle.
type SambaService struct {
	cfg         *config.Config
	shares      *repository.ShareRepo
	configState *repository.ConfigStateRepo
	backups     *repository.ConfigBackupRepo
	versions    *repository.ConfigVersionRepo
	groups      *repository.SambaGroupRepo
	sysUser     *system.UserManager
	audit       *repository.AuditRepo
	log         *zap.Logger
}

func NewSambaService(
	cfg *config.Config,
	shares *repository.ShareRepo,
	configState *repository.ConfigStateRepo,
	backups *repository.ConfigBackupRepo,
	versions *repository.ConfigVersionRepo,
	groups *repository.SambaGroupRepo,
	sysUser *system.UserManager,
	audit *repository.AuditRepo,
	log *zap.Logger,
) *SambaService {
	return &SambaService{
		cfg:         cfg,
		shares:      shares,
		configState: configState,
		backups:     backups,
		versions:    versions,
		groups:      groups,
		sysUser:     sysUser,
		audit:       audit,
		log:         log,
	}
}

// ─── Share CRUD ───────────────────────────────────────────────────────────────

// CreateShare validates and persists a new Samba share.
func (s *SambaService) CreateShare(ctx context.Context, req *model.CreateShareRequest, actor *model.PanelUser, ip string) (*model.Share, error) {
	if err := s.validateShareRequest(req.Name, req.Path, req.CreateMask, req.DirMask, req.ACL); err != nil {
		return nil, err
	}

	// Check name uniqueness
	if _, err := s.shares.GetByName(req.Name); err == nil {
		return nil, fmt.Errorf("share %q already exists", req.Name)
	}

	now := time.Now().UTC()
	share := &model.Share{
		ID:         uuid.New().String(),
		Name:       req.Name,
		Path:       req.Path,
		Comment:    sanitizeComment(req.Comment),
		Enabled:    true,
		Browseable: req.Browseable,
		GuestOk:    req.GuestOk,
		ReadOnly:   req.ReadOnly,
		OwnerGroup: req.OwnerGroup,
		CreateMask: defaultMask(req.CreateMask, "0664"),
		DirMask:    defaultMask(req.DirMask, "0775"),
		ACL:        req.ACL,
		CreatedAt:  now,
		UpdatedAt:  now,
		CreatedBy:  actor.ID,
	}

	// Create the directory if it doesn't exist (best-effort)
	if err := s.sysUser.MakeDirectory(req.Path, share.DirMask); err != nil {
		s.log.Warn("could not create share directory", zap.String("path", req.Path), zap.Error(err))
	}
	// Set ownership if a group is specified
	if req.OwnerGroup != "" {
		if err := s.sysUser.SetDirectoryOwnership(req.Path, "root", req.OwnerGroup); err != nil {
			s.log.Warn("could not set directory ownership", zap.Error(err))
		}
	}

	if err := s.shares.Create(share); err != nil {
		return nil, fmt.Errorf("persist share: %w", err)
	}

	// Stage the updated config
	if err := s.stageConfig(); err != nil {
		s.log.Error("failed to stage config after share creation", zap.Error(err))
	}
	_ = s.configState.MarkPending()

	s.writeAudit(actor, model.ActionShareCreate, "share", share.ID, req.Name,
		fmt.Sprintf(`{"path":%q}`, req.Path), ip, true, "")

	return share, nil
}

// UpdateShare updates share properties and ACL.
func (s *SambaService) UpdateShare(ctx context.Context, shareID string, req *model.UpdateShareRequest, actor *model.PanelUser, ip string) (*model.Share, error) {
	share, err := s.shares.GetByID(shareID)
	if err != nil {
		return nil, fmt.Errorf("share not found: %w", err)
	}

	if len(req.ACL) > 0 {
		if err := validateACL(req.ACL); err != nil {
			return nil, err
		}
	}

	share.Comment = sanitizeComment(req.Comment)
	share.Browseable = req.Browseable
	share.GuestOk = req.GuestOk
	share.ReadOnly = req.ReadOnly
	share.Enabled = req.Enabled
	share.ACL = req.ACL
	share.UpdatedAt = time.Now().UTC()

	if err := s.shares.Update(share); err != nil {
		return nil, fmt.Errorf("update share: %w", err)
	}

	if err := s.stageConfig(); err != nil {
		s.log.Error("failed to stage config after share update", zap.Error(err))
	}
	_ = s.configState.MarkPending()

	s.writeAudit(actor, model.ActionShareUpdate, "share", shareID, share.Name,
		fmt.Sprintf(`{"enabled":%v}`, share.Enabled), ip, true, "")

	return share, nil
}

// DeleteShare removes a share from DB and updates staging.
func (s *SambaService) DeleteShare(ctx context.Context, shareID string, actor *model.PanelUser, ip string) error {
	share, err := s.shares.GetByID(shareID)
	if err != nil {
		return fmt.Errorf("share not found: %w", err)
	}

	if err := s.shares.Delete(shareID); err != nil {
		return fmt.Errorf("delete share: %w", err)
	}

	if err := s.stageConfig(); err != nil {
		s.log.Error("failed to stage config after share deletion", zap.Error(err))
	}
	_ = s.configState.MarkPending()

	s.writeAudit(actor, model.ActionShareDelete, "share", shareID, share.Name,
		`{}`, ip, true, "")
	return nil
}

func (s *SambaService) GetShare(id string) (*model.Share, error) {
	return s.shares.GetByID(id)
}

func (s *SambaService) ListShares(search string, limit, offset int) ([]*model.Share, int64, error) {
	return s.shares.List(search, limit, offset)
}

// ─── Config lifecycle ─────────────────────────────────────────────────────────

// GetConfigStatus returns the current config state.
func (s *SambaService) GetConfigStatus() (*model.ConfigStatus, error) {
	return s.configState.Get()
}

// ApplyConfig validates the staged config, writes it to smb.conf, and restarts Samba.
func (s *SambaService) ApplyConfig(ctx context.Context, actor *model.PanelUser, ip string) error {
	// Ensure staging file exists
	if _, err := os.Stat(s.cfg.SmbStagingPath); err != nil {
		// Generate fresh staging from DB
		if err := s.stageConfig(); err != nil {
			return fmt.Errorf("generate config: %w", err)
		}
	}

	// Validate with testparm
	out, err := s.sysUser.TestSambaConfig(s.cfg.SmbStagingPath)
	if err != nil {
		return fmt.Errorf("config validation failed: %s", out)
	}

	// Save config version before applying
	content, err := os.ReadFile(s.cfg.SmbStagingPath) //nolint:gosec
	if err != nil {
		return fmt.Errorf("read staging: %w", err)
	}
	version := &model.ConfigVersion{
		ID:        uuid.New().String(),
		Content:   string(content),
		CreatedAt: time.Now().UTC(),
		CreatedBy: actor.ID,
		Note:      "auto-saved before apply",
	}
	if err := s.versions.Create(version); err != nil {
		s.log.Warn("failed to save config version", zap.Error(err))
	}
	// Keep only 50 versions
	_ = s.versions.Prune(50)

	// Atomic apply
	if err := samba.ApplyStaging(s.cfg.SmbStagingPath, s.cfg.SmbConfPath, s.cfg.SmbBackupDir); err != nil {
		return fmt.Errorf("apply config: %w", err)
	}

	// Restart Samba
	if err := s.sysUser.RestartSamba(); err != nil {
		return fmt.Errorf("restart Samba: %w", err)
	}

	_ = s.configState.MarkApplied()

	s.writeAudit(actor, model.ActionConfigApply, "config", "", "smb.conf",
		`{}`, ip, true, "")

	s.log.Info("smb.conf applied and Samba restarted", zap.String("by", actor.Username))
	return nil
}

// BackupConfig creates a named backup of the current live smb.conf.
func (s *SambaService) BackupConfig(ctx context.Context, note string, actor *model.PanelUser, ip string) (*model.ConfigBackup, error) {
	content, err := os.ReadFile(s.cfg.SmbConfPath) //nolint:gosec
	if err != nil {
		return nil, fmt.Errorf("read smb.conf: %w", err)
	}

	if err := os.MkdirAll(s.cfg.SmbBackupDir, 0750); err != nil {
		return nil, fmt.Errorf("create backup dir: %w", err)
	}

	filename := fmt.Sprintf("smb.conf.manual.%s.bak", time.Now().UTC().Format("20060102T150405Z"))
	backupPath := filepath.Join(s.cfg.SmbBackupDir, filename)

	if err := os.WriteFile(backupPath, content, 0640); err != nil {
		return nil, fmt.Errorf("write backup: %w", err)
	}

	backup := &model.ConfigBackup{
		ID:        uuid.New().String(),
		Filename:  filename,
		CreatedAt: time.Now().UTC(),
		CreatedBy: actor.ID,
		Size:      int64(len(content)),
		Note:      sanitizeComment(note),
	}

	if err := s.backups.Create(backup); err != nil {
		return nil, fmt.Errorf("persist backup record: %w", err)
	}

	s.writeAudit(actor, model.ActionConfigBackup, "config", backup.ID, filename,
		fmt.Sprintf(`{"size":%d}`, backup.Size), ip, true, "")

	return backup, nil
}

// ListBackups returns config backup history.
func (s *SambaService) ListBackups(limit, offset int) ([]*model.ConfigBackup, int64, error) {
	return s.backups.List(limit, offset)
}

// ListVersions returns config version history.
func (s *SambaService) ListVersions(limit, offset int) ([]*model.ConfigVersion, int64, error) {
	return s.versions.List(limit, offset)
}

// GetVersionContent returns the smb.conf content of a specific version.
func (s *SambaService) GetVersionContent(id string) (string, error) {
	return s.versions.GetContent(id)
}

// ─── Group Management ─────────────────────────────────────────────────────────

// GroupService manages Samba groups.
type GroupService struct {
	groups      *repository.SambaGroupRepo
	users       *repository.SambaUserRepo
	configState *repository.ConfigStateRepo
	sysUser     *system.UserManager
	audit       *repository.AuditRepo
	log         *zap.Logger
}

func NewGroupService(
	groups *repository.SambaGroupRepo,
	users *repository.SambaUserRepo,
	configState *repository.ConfigStateRepo,
	sysUser *system.UserManager,
	audit *repository.AuditRepo,
	log *zap.Logger,
) *GroupService {
	return &GroupService{
		groups:      groups,
		users:       users,
		configState: configState,
		sysUser:     sysUser,
		audit:       audit,
		log:         log,
	}
}

func (s *GroupService) Create(ctx context.Context, req *model.CreateGroupRequest, actor *model.PanelUser, ip string) (*model.SambaGroup, error) {
	if !reValidUsername.MatchString(req.Name) {
		return nil, fmt.Errorf("invalid group name %q", req.Name)
	}

	if _, err := s.groups.GetByName(req.Name); err == nil {
		return nil, fmt.Errorf("group %q already exists", req.Name)
	}

	if err := s.sysUser.CreateGroup(req.Name); err != nil {
		return nil, fmt.Errorf("create OS group: %w", err)
	}

	now := time.Now().UTC()
	group := &model.SambaGroup{
		ID:          uuid.New().String(),
		Name:        req.Name,
		Description: req.Description,
		CreatedAt:   now,
		UpdatedAt:   now,
		CreatedBy:   actor.ID,
	}

	if err := s.groups.Create(group); err != nil {
		_ = s.sysUser.DeleteGroup(req.Name)
		return nil, fmt.Errorf("persist group: %w", err)
	}

	s.writeAudit(actor, model.ActionGroupCreate, "group", group.ID, req.Name,
		`{}`, ip, true, "")
	return group, nil
}

func (s *GroupService) Delete(ctx context.Context, groupID string, actor *model.PanelUser, ip string) error {
	group, err := s.groups.GetByID(groupID)
	if err != nil {
		return fmt.Errorf("group not found")
	}

	if err := s.sysUser.DeleteGroup(group.Name); err != nil {
		return fmt.Errorf("delete OS group: %w", err)
	}

	if err := s.groups.Delete(groupID); err != nil {
		return fmt.Errorf("delete DB record: %w", err)
	}

	s.writeAudit(actor, model.ActionGroupDelete, "group", groupID, group.Name,
		`{}`, ip, true, "")
	return nil
}

func (s *GroupService) AddMember(ctx context.Context, groupID, userID string, actor *model.PanelUser, ip string) error {
	group, err := s.groups.GetByID(groupID)
	if err != nil {
		return fmt.Errorf("group not found")
	}
	user, err := s.users.GetByID(userID)
	if err != nil {
		return fmt.Errorf("user not found")
	}

	already, _ := s.groups.IsMember(groupID, userID)
	if already {
		return fmt.Errorf("user is already a member")
	}

	if err := s.sysUser.AddUserToGroup(user.Username, group.Name); err != nil {
		return fmt.Errorf("add to OS group: %w", err)
	}
	if err := s.groups.AddMember(groupID, userID, actor.ID); err != nil {
		return fmt.Errorf("add to DB group: %w", err)
	}

	s.writeAudit(actor, model.ActionGroupAddMember, "group", groupID, group.Name,
		fmt.Sprintf(`{"user":%q}`, user.Username), ip, true, "")
	return nil
}

func (s *GroupService) RemoveMember(ctx context.Context, groupID, userID string, actor *model.PanelUser, ip string) error {
	group, err := s.groups.GetByID(groupID)
	if err != nil {
		return fmt.Errorf("group not found")
	}
	user, err := s.users.GetByID(userID)
	if err != nil {
		return fmt.Errorf("user not found")
	}

	if err := s.sysUser.RemoveUserFromGroup(user.Username, group.Name); err != nil {
		return fmt.Errorf("remove from OS group: %w", err)
	}
	if err := s.groups.RemoveMember(groupID, userID); err != nil {
		return fmt.Errorf("remove from DB group: %w", err)
	}

	s.writeAudit(actor, model.ActionGroupRmMember, "group", groupID, group.Name,
		fmt.Sprintf(`{"user":%q}`, user.Username), ip, true, "")
	return nil
}

func (s *GroupService) GetByID(id string) (*model.SambaGroup, error) {
	return s.groups.GetByID(id)
}

func (s *GroupService) List(search string, limit, offset int) ([]*model.SambaGroup, int64, error) {
	return s.groups.List(search, limit, offset)
}

// ─── Internal helpers ─────────────────────────────────────────────────────────

// stageConfig regenerates the staging smb.conf from the current DB state.
func (s *SambaService) stageConfig() error {
	shares, err := s.shares.ListAll()
	if err != nil {
		return fmt.Errorf("list shares: %w", err)
	}

	builder := samba.NewBuilder()

	// Try to preserve existing global options
	if existing, err := samba.ParseFile(s.cfg.SmbConfPath); err == nil {
		builder.MergeGlobalFrom(existing.Global)
	}

	content, err := builder.Build(shares)
	if err != nil {
		return fmt.Errorf("build config: %w", err)
	}

	return samba.WriteStaging(s.cfg.SmbStagingPath, content)
}

func (s *SambaService) validateShareRequest(name, path, createMask, dirMask string, acl []model.ShareACLEntry) error {
	if !reShareName.MatchString(name) {
		return fmt.Errorf("invalid share name %q: must be 1-80 alphanumeric chars", name)
	}
	for _, reserved := range []string{"global", "printers", "print$", "homes", "ipc$"} {
		if strings.EqualFold(name, reserved) {
			return fmt.Errorf("share name %q is reserved", name)
		}
	}
	if !strings.HasPrefix(path, "/") || !reAbsPath.MatchString(path) || strings.Contains(path, "..") {
		return fmt.Errorf("invalid or unsafe share path %q", path)
	}
	if createMask != "" && !reOctalMode.MatchString(createMask) {
		return fmt.Errorf("create_mask must be octal like 0664")
	}
	if dirMask != "" && !reOctalMode.MatchString(dirMask) {
		return fmt.Errorf("dir_mask must be octal like 0775")
	}
	return validateACL(acl)
}

func validateACL(acl []model.ShareACLEntry) error {
	rePrincipal := regexp.MustCompile(`^@?[a-z_][a-z0-9_-]{0,30}$`)
	for _, e := range acl {
		if !rePrincipal.MatchString(e.Principal) {
			return fmt.Errorf("invalid ACL principal %q", e.Principal)
		}
		if e.Permission != model.PermReadOnly && e.Permission != model.PermReadWrite {
			return fmt.Errorf("invalid permission %q", e.Permission)
		}
	}
	return nil
}

func sanitizeComment(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	s = strings.ReplaceAll(s, "#", "")
	s = strings.ReplaceAll(s, ";", "")
	if len(s) > 256 {
		s = s[:256]
	}
	return strings.TrimSpace(s)
}

func defaultMask(mask, fallback string) string {
	if reOctalMode.MatchString(mask) {
		return mask
	}
	return fallback
}

func (s *SambaService) writeAudit(actor *model.PanelUser, action model.AuditAction,
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

func (s *GroupService) writeAudit(actor *model.PanelUser, action model.AuditAction,
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
