package model

import "time"

// ─── Panel Users (admin panel accounts) ──────────────────────────────────────

// Role defines what a panel user can do.
type Role string

const (
	RoleAdmin    Role = "admin"    // full access
	RoleOperator Role = "operator" // manage users/shares, no panel-user management
	RoleViewer   Role = "viewer"   // read-only access to everything
)

// PanelUser represents an account that can log into the management panel.
type PanelUser struct {
	ID                string    `json:"id"`
	Username          string    `json:"username"`
	PasswordHash      string    `json:"-"` // never expose
	Role              Role      `json:"role"`
	Email             string    `json:"email"`
	MustChangePass    bool      `json:"must_change_password"`
	Disabled          bool      `json:"disabled"`
	LastLoginAt       *time.Time `json:"last_login_at,omitempty"`
	FailedLoginCount  int       `json:"-"`
	LockedUntil       *time.Time `json:"-"`
	CreatedAt         time.Time `json:"created_at"`
	UpdatedAt         time.Time `json:"updated_at"`
}

// ─── Samba Users (OS-level accounts for Samba) ───────────────────────────────

// SambaUserStatus represents the Samba account status.
type SambaUserStatus string

const (
	SambaUserEnabled  SambaUserStatus = "enabled"
	SambaUserDisabled SambaUserStatus = "disabled"
)

// SambaUser represents a Linux/Samba user managed by this panel.
// These users have NO shell access, NO home directory, and NO SSH login.
type SambaUser struct {
	ID          string          `json:"id"`
	Username    string          `json:"username"`
	DisplayName string          `json:"display_name"`
	Status      SambaUserStatus `json:"status"`
	Groups      []string        `json:"groups"` // group names
	Comment     string          `json:"comment"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
	CreatedBy   string          `json:"created_by"` // panel user ID
}

// ─── Samba Groups (Linux groups mapped to Samba) ─────────────────────────────

// SambaGroup represents a Linux group used for Samba access control.
type SambaGroup struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	Description string    `json:"description"`
	Members     []string  `json:"members"` // samba user IDs
	CreatedAt   time.Time `json:"created_at"`
	UpdatedAt   time.Time `json:"updated_at"`
	CreatedBy   string    `json:"created_by"`
}

// ─── Shares ───────────────────────────────────────────────────────────────────

// SharePermission defines access level for a user/group on a share.
type SharePermission string

const (
	PermReadOnly  SharePermission = "read_only"
	PermReadWrite SharePermission = "read_write"
)

// ShareACLEntry represents an access control entry on a share.
type ShareACLEntry struct {
	Principal  string          `json:"principal"`   // username or @groupname
	Permission SharePermission `json:"permission"`
}

// Share represents a Samba share definition.
type Share struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`        // share name (e.g., "documents")
	Path        string          `json:"path"`        // filesystem path
	Comment     string          `json:"comment"`
	Enabled     bool            `json:"enabled"`
	Browseable  bool            `json:"browseable"`
	GuestOk     bool            `json:"guest_ok"`
	ReadOnly    bool            `json:"read_only"`   // global read-only flag
	ACL         []ShareACLEntry `json:"acl"`         // per-user/group ACLs
	ValidUsers  []string        `json:"valid_users"` // allowed principals
	WriteList   []string        `json:"write_list"`  // principals with write
	OwnerGroup  string          `json:"owner_group"` // Linux group owning the dir
	CreateMask  string          `json:"create_mask"`
	DirMask     string          `json:"dir_mask"`
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
	CreatedBy   string          `json:"created_by"`
}

// ─── Config State ─────────────────────────────────────────────────────────────

// ConfigStatus represents the current state of smb.conf.
type ConfigStatus struct {
	HasPendingChanges bool      `json:"has_pending_changes"`
	LastAppliedAt     *time.Time `json:"last_applied_at,omitempty"`
	LastModifiedAt    *time.Time `json:"last_modified_at,omitempty"`
	PendingSince      *time.Time `json:"pending_since,omitempty"`
}

// ConfigBackup represents a stored smb.conf backup.
type ConfigBackup struct {
	ID        string    `json:"id"`
	Filename  string    `json:"filename"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
	Size      int64     `json:"size_bytes"`
	Note      string    `json:"note"`
}

// ConfigVersion represents a version entry in config history.
type ConfigVersion struct {
	ID        string    `json:"id"`
	Content   string    `json:"content"`
	CreatedAt time.Time `json:"created_at"`
	CreatedBy string    `json:"created_by"`
	Note      string    `json:"note"`
}

// ─── Audit Log ────────────────────────────────────────────────────────────────

// AuditAction describes the type of action performed.
type AuditAction string

const (
	ActionLogin          AuditAction = "LOGIN"
	ActionLogout         AuditAction = "LOGOUT"
	ActionLoginFailed    AuditAction = "LOGIN_FAILED"
	ActionUserCreate     AuditAction = "USER_CREATE"
	ActionUserUpdate     AuditAction = "USER_UPDATE"
	ActionUserDelete     AuditAction = "USER_DELETE"
	ActionUserPassChange AuditAction = "USER_PASS_CHANGE"
	ActionUserEnable     AuditAction = "USER_ENABLE"
	ActionUserDisable    AuditAction = "USER_DISABLE"
	ActionGroupCreate    AuditAction = "GROUP_CREATE"
	ActionGroupUpdate    AuditAction = "GROUP_UPDATE"
	ActionGroupDelete    AuditAction = "GROUP_DELETE"
	ActionGroupAddMember AuditAction = "GROUP_ADD_MEMBER"
	ActionGroupRmMember  AuditAction = "GROUP_REMOVE_MEMBER"
	ActionShareCreate    AuditAction = "SHARE_CREATE"
	ActionShareUpdate    AuditAction = "SHARE_UPDATE"
	ActionShareDelete    AuditAction = "SHARE_DELETE"
	ActionConfigApply    AuditAction = "CONFIG_APPLY"
	ActionConfigBackup   AuditAction = "CONFIG_BACKUP"
	ActionConfigRestore  AuditAction = "CONFIG_RESTORE"
	ActionPanelUserCreate AuditAction = "PANEL_USER_CREATE"
	ActionPanelUserUpdate AuditAction = "PANEL_USER_UPDATE"
	ActionPanelUserDelete AuditAction = "PANEL_USER_DELETE"
)

// AuditLog represents a single audit log entry.
type AuditLog struct {
	ID         string      `json:"id"`
	Timestamp  time.Time   `json:"timestamp"`
	ActorID    string      `json:"actor_id"`    // panel user ID
	ActorName  string      `json:"actor_name"`  // panel username
	Action     AuditAction `json:"action"`
	TargetType string      `json:"target_type"` // "samba_user", "share", etc.
	TargetID   string      `json:"target_id"`
	TargetName string      `json:"target_name"`
	Details    string      `json:"details"` // JSON string with additional info
	IPAddress  string      `json:"ip_address"`
	Success    bool        `json:"success"`
	ErrorMsg   string      `json:"error_message,omitempty"`
}

// ─── Auth ─────────────────────────────────────────────────────────────────────

// TokenPair holds an access + refresh token pair.
type TokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	ExpiresIn    int    `json:"expires_in"` // seconds until access token expires
}

// Claims holds the JWT payload.
type Claims struct {
	UserID   string `json:"uid"`
	Username string `json:"usr"`
	Role     Role   `json:"role"`
	TokenType string `json:"typ"` // "access" | "refresh"
}

// LoginRequest is the JSON body for POST /api/v1/auth/login
type LoginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// ─── Request/Response DTOs ────────────────────────────────────────────────────

// CreateSambaUserRequest is the DTO for creating a Samba user.
type CreateSambaUserRequest struct {
	Username    string `json:"username"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name"`
	Comment     string `json:"comment"`
	Groups      []string `json:"groups"`
}

// UpdateSambaUserRequest is the DTO for updating a Samba user.
type UpdateSambaUserRequest struct {
	DisplayName string `json:"display_name"`
	Comment     string `json:"comment"`
	Status      SambaUserStatus `json:"status"`
}

// ChangeSambaPasswordRequest is the DTO for changing a Samba user's password.
type ChangeSambaPasswordRequest struct {
	NewPassword string `json:"new_password"`
}

// CreateGroupRequest is the DTO for creating a Samba group.
type CreateGroupRequest struct {
	Name        string `json:"name"`
	Description string `json:"description"`
}

// CreateShareRequest is the DTO for creating a share.
type CreateShareRequest struct {
	Name        string          `json:"name"`
	Path        string          `json:"path"`
	Comment     string          `json:"comment"`
	Browseable  bool            `json:"browseable"`
	GuestOk     bool            `json:"guest_ok"`
	ReadOnly    bool            `json:"read_only"`
	OwnerGroup  string          `json:"owner_group"`
	CreateMask  string          `json:"create_mask"`
	DirMask     string          `json:"dir_mask"`
	ACL         []ShareACLEntry `json:"acl"`
}

// UpdateShareRequest is the DTO for updating a share.
type UpdateShareRequest struct {
	Comment    string          `json:"comment"`
	Browseable bool            `json:"browseable"`
	GuestOk    bool            `json:"guest_ok"`
	ReadOnly   bool            `json:"read_only"`
	Enabled    bool            `json:"enabled"`
	ACL        []ShareACLEntry `json:"acl"`
}

// AuditLogFilter defines filtering options for audit log queries.
type AuditLogFilter struct {
	ActorID    string
	Action     AuditAction
	TargetType string
	Since      *time.Time
	Until      *time.Time
	Limit      int
	Offset     int
	Search     string
}

// PanelUserFilter defines filtering options for panel user queries.
type PanelUserFilter struct {
	Role   Role
	Search string
	Limit  int
	Offset int
}

// SambaUserFilter defines filtering options for Samba user queries.
type SambaUserFilter struct {
	Status SambaUserStatus
	Group  string
	Search string
	Limit  int
	Offset int
}

// APIError is the standard error response body.
type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
}

// APIResponse is a generic success response wrapper.
type APIResponse[T any] struct {
	Data    T      `json:"data"`
	Message string `json:"message,omitempty"`
}

// PaginatedResponse wraps a list response with pagination info.
type PaginatedResponse[T any] struct {
	Items  []T   `json:"items"`
	Total  int64 `json:"total"`
	Limit  int   `json:"limit"`
	Offset int   `json:"offset"`
}
