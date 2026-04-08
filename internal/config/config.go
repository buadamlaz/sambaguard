package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
)

// Config holds all application configuration loaded from environment variables.
// No sensitive defaults are baked in — all secrets must be explicitly provided.
type Config struct {
	// Server
	Host        string
	Port        int
	Environment string // "development" | "production"

	// Security
	JWTSecret          string // min 32 bytes
	JWTAccessExpiry    int    // minutes
	JWTRefreshExpiry   int    // hours
	CSRFSecret         string // min 32 bytes
	BCryptCost         int
	RateLimitLogin     int // max login attempts per window
	RateLimitWindowSec int // rate limit window in seconds

	// Database
	DatabasePath string

	// Samba
	SmbConfPath    string // path to smb.conf
	SmbStagingPath string // path to staged smb.conf (before apply)
	SmbBackupDir   string // directory for config backups
	SambaUser      string // OS user that owns samba config files

	// Logging
	LogLevel  string // "debug" | "info" | "warn" | "error"
	AuditFile string // path to write audit log (in addition to DB)

	// TLS (optional)
	TLSCertFile string
	TLSKeyFile  string

	// Session
	SessionTimeout int // minutes of inactivity before session expires

	// Initial admin (used only for first-run bootstrap)
	InitAdminUser string
	InitAdminPass string
}

// Load reads configuration from environment variables with validation.
func Load() (*Config, error) {
	cfg := &Config{
		Host:               getEnv("HOST", "0.0.0.0"),
		Port:               getEnvInt("PORT", 8090),
		Environment:        getEnv("ENVIRONMENT", "production"),
		JWTSecret:          os.Getenv("JWT_SECRET"),
		JWTAccessExpiry:    getEnvInt("JWT_ACCESS_EXPIRY_MINUTES", 15),
		JWTRefreshExpiry:   getEnvInt("JWT_REFRESH_EXPIRY_HOURS", 168),
		CSRFSecret:         os.Getenv("CSRF_SECRET"),
		BCryptCost:         getEnvInt("BCRYPT_COST", 12),
		RateLimitLogin:     getEnvInt("RATE_LIMIT_LOGIN_ATTEMPTS", 5),
		RateLimitWindowSec: getEnvInt("RATE_LIMIT_WINDOW_SECONDS", 900),
		DatabasePath:       getEnv("DATABASE_PATH", "/var/lib/samba-panel/panel.db"),
		SmbConfPath:        getEnv("SMB_CONF_PATH", "/etc/samba/smb.conf"),
		SmbStagingPath:     getEnv("SMB_STAGING_PATH", "/var/lib/samba-panel/smb.conf.staging"),
		SmbBackupDir:       getEnv("SMB_BACKUP_DIR", "/var/lib/samba-panel/backups"),
		SambaUser:          getEnv("SAMBA_USER", "root"),
		LogLevel:           getEnv("LOG_LEVEL", "info"),
		AuditFile:          getEnv("AUDIT_FILE", "/var/log/samba-panel/audit.log"),
		TLSCertFile:        os.Getenv("TLS_CERT_FILE"),
		TLSKeyFile:         os.Getenv("TLS_KEY_FILE"),
		SessionTimeout:     getEnvInt("SESSION_TIMEOUT_MINUTES", 60),
		InitAdminUser:      getEnv("INIT_ADMIN_USER", "admin"),
		InitAdminPass:      os.Getenv("INIT_ADMIN_PASS"),
	}

	return cfg, cfg.validate()
}

func (c *Config) validate() error {
	var errs []string

	if len(c.JWTSecret) < 32 {
		errs = append(errs, "JWT_SECRET must be at least 32 characters")
	}
	if len(c.CSRFSecret) < 32 {
		errs = append(errs, "CSRF_SECRET must be at least 32 characters")
	}
	if c.BCryptCost < 10 || c.BCryptCost > 14 {
		errs = append(errs, "BCRYPT_COST must be between 10 and 14")
	}
	if c.Port < 1 || c.Port > 65535 {
		errs = append(errs, "PORT must be between 1 and 65535")
	}
	if c.Environment != "development" && c.Environment != "production" {
		errs = append(errs, "ENVIRONMENT must be 'development' or 'production'")
	}
	// TLS: if one is set, both must be set
	if (c.TLSCertFile == "") != (c.TLSKeyFile == "") {
		errs = append(errs, "TLS_CERT_FILE and TLS_KEY_FILE must both be set or both unset")
	}

	if len(errs) > 0 {
		return errors.New("configuration errors:\n  - " + strings.Join(errs, "\n  - "))
	}
	return nil
}

// IsTLS returns true if TLS is configured.
func (c *Config) IsTLS() bool {
	return c.TLSCertFile != "" && c.TLSKeyFile != ""
}

// ListenAddr returns the combined host:port string.
func (c *Config) ListenAddr() string {
	return fmt.Sprintf("%s:%d", c.Host, c.Port)
}

func getEnv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func getEnvInt(key string, fallback int) int {
	if v := os.Getenv(key); v != "" {
		i, err := strconv.Atoi(v)
		if err == nil {
			return i
		}
	}
	return fallback
}
