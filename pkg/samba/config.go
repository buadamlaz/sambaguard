// Package samba handles parsing, building, and writing of smb.conf files.
// It never writes directly — it stages changes and applies them atomically
// after validation.
package samba

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/buadamlaz/sambaguard/internal/model"
)

// Section represents a single [section] block in smb.conf.
type Section struct {
	Name    string
	Options map[string]string
	Order   []string // preserves key insertion order
}

// Config represents a parsed smb.conf file.
type Config struct {
	Global   *Section
	Shares   map[string]*Section // key = share name
	ShareOrder []string          // preserves section order
}

var reValidShareName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9 _-]{0,79}$`)

// ─── Parsing ──────────────────────────────────────────────────────────────────

// ParseFile reads and parses an smb.conf file.
func ParseFile(path string) (*Config, error) {
	f, err := os.Open(path) //nolint:gosec // path is validated by caller
	if err != nil {
		return nil, fmt.Errorf("open smb.conf: %w", err)
	}
	defer f.Close()

	cfg := &Config{
		Global: &Section{Name: "global", Options: make(map[string]string)},
		Shares: make(map[string]*Section),
	}

	var current *Section
	scanner := bufio.NewScanner(f)
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and blank lines
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}

		// Section header: [name]
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			name := strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			if name == "global" {
				current = cfg.Global
			} else {
				s := &Section{Name: name, Options: make(map[string]string)}
				cfg.Shares[name] = s
				cfg.ShareOrder = append(cfg.ShareOrder, name)
				current = s
			}
			continue
		}

		// Key = Value pair
		if current == nil {
			continue // orphan line before any section
		}

		if idx := strings.IndexByte(line, '='); idx > 0 {
			key := strings.TrimSpace(line[:idx])
			val := strings.TrimSpace(line[idx+1:])
			// Normalise key: lowercase, collapse spaces
			normKey := strings.ToLower(strings.Join(strings.Fields(key), " "))
			if _, exists := current.Options[normKey]; !exists {
				current.Order = append(current.Order, normKey)
			}
			current.Options[normKey] = val
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("scan smb.conf: %w", err)
	}

	return cfg, nil
}

// ─── Building ─────────────────────────────────────────────────────────────────

// Builder constructs an smb.conf from panel data.
type Builder struct {
	globalOpts map[string]string
}

// NewBuilder creates a Builder with sensible, secure defaults for the global section.
func NewBuilder() *Builder {
	return &Builder{
		globalOpts: map[string]string{
			"workgroup":              "WORKGROUP",
			"server string":         "Samba Server",
			"security":              "user",
			"map to guest":          "Bad User",
			"dns proxy":             "no",
			"log level":             "1",
			"max log size":          "50",
			"panic action":          "/usr/share/samba/panic-action %d",
			"server role":           "standalone server",
			"obey pam restrictions": "yes",
			"unix password sync":    "no",
			"passwd program":        "/usr/bin/passwd %u",
			"passwd chat":           "*Enter\\snew\\s*\\spassword:* %n\\n *Retype\\snew\\s*\\spassword:* %n\\n *password\\supdated\\ssuccessfully* .",
			"pam password change":   "yes",
			"usershare allow guests": "no",
		},
	}
}

// SetGlobalOption sets or overrides a global smb.conf option.
func (b *Builder) SetGlobalOption(key, value string) {
	b.globalOpts[strings.ToLower(key)] = value
}

// MergeGlobalFrom copies options from an existing parsed global section,
// allowing customisation outside the panel to be preserved.
func (b *Builder) MergeGlobalFrom(s *Section) {
	for k, v := range s.Options {
		if _, exists := b.globalOpts[k]; !exists {
			b.globalOpts[k] = v
		}
	}
}

// Build generates the full smb.conf content from the given shares.
func (b *Builder) Build(shares []*model.Share) (string, error) {
	var sb strings.Builder

	// Header comment
	sb.WriteString(fmt.Sprintf(
		"# Managed by Samba Panel — do not edit manually\n"+
			"# Generated at: %s\n\n",
		time.Now().UTC().Format(time.RFC3339),
	))

	// [global] section
	sb.WriteString("[global]\n")
	// Deterministic order for global opts
	globalKeyOrder := []string{
		"workgroup", "server string", "server role", "security",
		"map to guest", "usershare allow guests",
		"obey pam restrictions", "unix password sync", "pam password change",
		"passwd program", "passwd chat",
		"dns proxy", "log level", "max log size", "panic action",
	}
	written := map[string]bool{}
	for _, k := range globalKeyOrder {
		if v, ok := b.globalOpts[k]; ok {
			fmt.Fprintf(&sb, "   %-30s = %s\n", k, v)
			written[k] = true
		}
	}
	// Any remaining custom global opts
	for k, v := range b.globalOpts {
		if !written[k] {
			fmt.Fprintf(&sb, "   %-30s = %s\n", k, v)
		}
	}
	sb.WriteString("\n")

	// Share sections
	for _, share := range shares {
		if !share.Enabled {
			continue
		}
		section, err := buildShareSection(share)
		if err != nil {
			return "", fmt.Errorf("build share %q: %w", share.Name, err)
		}
		sb.WriteString(section)
	}

	return sb.String(), nil
}

// buildShareSection converts a Share model into an smb.conf section string.
func buildShareSection(s *model.Share) (string, error) {
	if err := validateShareName(s.Name); err != nil {
		return "", err
	}
	if err := validatePath(s.Path); err != nil {
		return "", err
	}

	var sb strings.Builder
	fmt.Fprintf(&sb, "[%s]\n", s.Name)
	fmt.Fprintf(&sb, "   %-30s = %s\n", "path", s.Path)

	if s.Comment != "" {
		fmt.Fprintf(&sb, "   %-30s = %s\n", "comment", sanitizeInlineValue(s.Comment))
	}

	boolStr := func(b bool) string {
		if b {
			return "yes"
		}
		return "no"
	}

	fmt.Fprintf(&sb, "   %-30s = %s\n", "browseable", boolStr(s.Browseable))
	fmt.Fprintf(&sb, "   %-30s = %s\n", "read only", boolStr(s.ReadOnly))
	fmt.Fprintf(&sb, "   %-30s = %s\n", "guest ok", boolStr(s.GuestOk))

	if s.CreateMask != "" {
		fmt.Fprintf(&sb, "   %-30s = %s\n", "create mask", s.CreateMask)
	}
	if s.DirMask != "" {
		fmt.Fprintf(&sb, "   %-30s = %s\n", "directory mask", s.DirMask)
	}

	// Build valid users and write list from ACL
	var validUsers, writeList []string
	for _, entry := range s.ACL {
		principal := formatPrincipal(entry.Principal)
		validUsers = append(validUsers, principal)
		if entry.Permission == model.PermReadWrite {
			writeList = append(writeList, principal)
		}
	}

	if len(validUsers) > 0 {
		fmt.Fprintf(&sb, "   %-30s = %s\n", "valid users", strings.Join(validUsers, " "))
	}
	if len(writeList) > 0 {
		fmt.Fprintf(&sb, "   %-30s = %s\n", "write list", strings.Join(writeList, " "))
	}

	sb.WriteString("\n")
	return sb.String(), nil
}

// formatPrincipal ensures group names are prefixed with '@'.
// If the principal starts with '@', it's a group; otherwise it's a user.
func formatPrincipal(p string) string {
	p = strings.TrimSpace(p)
	if strings.HasPrefix(p, "@") {
		return p
	}
	return p // user principal — no prefix in Samba
}

// ─── Atomic write ─────────────────────────────────────────────────────────────

// WriteStaging writes content to the staging path atomically
// (write to temp → rename), so a partial write never corrupts the file.
func WriteStaging(stagingPath, content string) error {
	dir := filepath.Dir(stagingPath)
	if err := os.MkdirAll(dir, 0750); err != nil {
		return fmt.Errorf("create staging dir: %w", err)
	}

	tmp, err := os.CreateTemp(dir, "smb.conf.staging.*")
	if err != nil {
		return fmt.Errorf("create temp file: %w", err)
	}
	tmpName := tmp.Name()

	defer func() {
		tmp.Close()
		os.Remove(tmpName) // clean up temp if rename failed
	}()

	if _, err := tmp.WriteString(content); err != nil {
		return fmt.Errorf("write staging: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync staging: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close staging: %w", err)
	}

	if err := os.Rename(tmpName, stagingPath); err != nil {
		return fmt.Errorf("rename staging: %w", err)
	}
	return nil
}

// ApplyStaging atomically replaces the live smb.conf with the staged version.
// It first backs up the current config.
func ApplyStaging(stagingPath, livePath, backupDir string) error {
	// Read staged config
	staged, err := os.ReadFile(stagingPath) //nolint:gosec
	if err != nil {
		return fmt.Errorf("read staging: %w", err)
	}

	// Backup current live config
	if _, err := os.Stat(livePath); err == nil {
		if err := os.MkdirAll(backupDir, 0750); err != nil {
			return fmt.Errorf("create backup dir: %w", err)
		}
		backupName := filepath.Join(backupDir,
			fmt.Sprintf("smb.conf.%s.bak", time.Now().UTC().Format("20060102T150405Z")))
		current, err := os.ReadFile(livePath) //nolint:gosec
		if err != nil {
			return fmt.Errorf("read current config: %w", err)
		}
		if err := os.WriteFile(backupName, current, 0640); err != nil {
			return fmt.Errorf("write backup: %w", err)
		}
	}

	// Write to temp file next to live path
	dir := filepath.Dir(livePath)
	tmp, err := os.CreateTemp(dir, "smb.conf.apply.*")
	if err != nil {
		return fmt.Errorf("create apply temp: %w", err)
	}
	tmpName := tmp.Name()
	defer func() {
		tmp.Close()
		os.Remove(tmpName)
	}()

	if _, err := tmp.Write(staged); err != nil {
		return fmt.Errorf("write apply temp: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		return fmt.Errorf("sync apply temp: %w", err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("close apply temp: %w", err)
	}

	// Set proper permissions before moving into place
	if err := os.Chmod(tmpName, 0640); err != nil {
		return fmt.Errorf("chmod apply temp: %w", err)
	}

	// Atomic rename
	if err := os.Rename(tmpName, livePath); err != nil {
		return fmt.Errorf("rename to live: %w", err)
	}
	return nil
}

// ─── Validation ───────────────────────────────────────────────────────────────

func validateShareName(name string) error {
	if !reValidShareName.MatchString(name) {
		return fmt.Errorf("invalid share name %q", name)
	}
	// Reserved names
	for _, reserved := range []string{"global", "printers", "print$", "homes", "ipc$"} {
		if strings.EqualFold(name, reserved) {
			return fmt.Errorf("share name %q is reserved", name)
		}
	}
	return nil
}

func validatePath(p string) error {
	if !strings.HasPrefix(p, "/") {
		return fmt.Errorf("share path must be absolute: %q", p)
	}
	if strings.Contains(p, "..") {
		return fmt.Errorf("share path must not contain '..': %q", p)
	}
	if strings.ContainsRune(p, 0) {
		return fmt.Errorf("share path must not contain null bytes")
	}
	return nil
}

// sanitizeInlineValue strips characters that could inject new lines into smb.conf.
func sanitizeInlineValue(s string) string {
	s = strings.ReplaceAll(s, "\n", " ")
	s = strings.ReplaceAll(s, "\r", " ")
	// Remove smb.conf comment characters mid-value
	s = strings.ReplaceAll(s, "#", "")
	s = strings.ReplaceAll(s, ";", "")
	return strings.TrimSpace(s)
}
