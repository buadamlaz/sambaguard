// Package system provides safe wrappers around Linux system administration
// commands. ALL calls use exec.Command with explicit argument lists — never
// shell interpolation — to prevent command injection.
package system

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"
)

// validation patterns — applied before any argument is passed to a subprocess
var (
	reUsername  = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,30}$`)
	reGroupName = regexp.MustCompile(`^[a-z_][a-z0-9_-]{0,30}$`)
	rePassword  = regexp.MustCompile(`^.{8,128}$`) // min 8, max 128 chars
)

const execTimeout = 30 * time.Second

// UserManager performs OS-level user/group operations.
// Methods run with the privileges of the calling process (typically root in
// Docker or via sudo). Operations are designed to be idempotent where possible.
type UserManager struct{}

// NewUserManager creates a new UserManager.
func NewUserManager() *UserManager {
	return &UserManager{}
}

// ─── Linux User Operations ────────────────────────────────────────────────────

// CreateSambaUser creates a system account that:
//   - has no home directory (-M)
//   - has no shell access (-s /usr/sbin/nologin)
//   - is a system account (-r)
//   - cannot be used for SSH login (nologin shell enforces this)
func (m *UserManager) CreateSambaUser(username string) error {
	if err := validateUsername(username); err != nil {
		return err
	}

	// Check if user already exists in OS
	if exists, err := m.UserExists(username); err != nil {
		return fmt.Errorf("check user existence: %w", err)
	} else if exists {
		return fmt.Errorf("system user %q already exists", username)
	}

	// useradd -r -s /usr/sbin/nologin -M -c "Samba user" <username>
	// -r: system account (UID in system range, no expiry by default)
	// -s /usr/sbin/nologin: no interactive shell
	// -M: do NOT create home directory
	// -c: comment/GECOS field
	_, err := runCmd("useradd",
		"-r",
		"-s", "/usr/sbin/nologin",
		"-M",
		"-c", "Samba managed user",
		username,
	)
	if err != nil {
		return fmt.Errorf("useradd failed: %w", err)
	}
	return nil
}

// DeleteSambaUser removes the system account and its Samba password entry.
func (m *UserManager) DeleteSambaUser(username string) error {
	if err := validateUsername(username); err != nil {
		return err
	}

	// Remove from Samba password database first
	_ = m.RemoveSambaPassword(username) // best-effort

	// userdel <username>
	// We do NOT use -r because there's no home directory to remove.
	_, err := runCmd("userdel", username)
	if err != nil {
		// If user doesn't exist, treat as success
		if strings.Contains(err.Error(), "does not exist") {
			return nil
		}
		return fmt.Errorf("userdel failed: %w", err)
	}
	return nil
}

// UserExists checks whether a Linux user account exists.
func (m *UserManager) UserExists(username string) (bool, error) {
	if err := validateUsername(username); err != nil {
		return false, err
	}
	_, err := runCmd("id", "-u", username)
	if err != nil {
		// exit code 1 from `id` means user doesn't exist — not an error for us
		return false, nil
	}
	return true, nil
}

// ─── Samba Password Operations ────────────────────────────────────────────────

// SetSambaPassword sets or updates a user's Samba password.
// The password is passed via stdin to smbpasswd, never via command arguments.
func (m *UserManager) SetSambaPassword(username, password string) error {
	if err := validateUsername(username); err != nil {
		return err
	}
	if err := validatePassword(password); err != nil {
		return err
	}

	// smbpasswd -a (add/update) -s (silent/stdin mode) <username>
	// Password is written to stdin: newpass\nnewpass\n (confirmation)
	stdin := fmt.Sprintf("%s\n%s\n", password, password)
	_, err := runCmdWithStdin(stdin, "smbpasswd", "-a", "-s", username)
	if err != nil {
		return fmt.Errorf("smbpasswd set failed: %w", err)
	}
	return nil
}

// EnableSambaUser enables a previously disabled Samba account.
func (m *UserManager) EnableSambaUser(username string) error {
	if err := validateUsername(username); err != nil {
		return err
	}
	_, err := runCmd("smbpasswd", "-e", username)
	if err != nil {
		return fmt.Errorf("smbpasswd enable failed: %w", err)
	}
	return nil
}

// DisableSambaUser disables a Samba account without deleting it.
func (m *UserManager) DisableSambaUser(username string) error {
	if err := validateUsername(username); err != nil {
		return err
	}
	_, err := runCmd("smbpasswd", "-d", username)
	if err != nil {
		return fmt.Errorf("smbpasswd disable failed: %w", err)
	}
	return nil
}

// RemoveSambaPassword removes the user from Samba's password database.
func (m *UserManager) RemoveSambaPassword(username string) error {
	if err := validateUsername(username); err != nil {
		return err
	}
	_, err := runCmd("smbpasswd", "-x", username)
	return err
}

// ─── Group Operations ─────────────────────────────────────────────────────────

// CreateGroup creates a new Linux group.
func (m *UserManager) CreateGroup(groupName string) error {
	if err := validateGroupName(groupName); err != nil {
		return err
	}

	if exists, err := m.GroupExists(groupName); err != nil {
		return fmt.Errorf("check group existence: %w", err)
	} else if exists {
		return fmt.Errorf("group %q already exists", groupName)
	}

	// groupadd -r <groupname>  (-r = system group)
	_, err := runCmd("groupadd", "-r", groupName)
	if err != nil {
		return fmt.Errorf("groupadd failed: %w", err)
	}
	return nil
}

// DeleteGroup removes a Linux group.
func (m *UserManager) DeleteGroup(groupName string) error {
	if err := validateGroupName(groupName); err != nil {
		return err
	}
	_, err := runCmd("groupdel", groupName)
	if err != nil {
		if strings.Contains(err.Error(), "does not exist") {
			return nil
		}
		return fmt.Errorf("groupdel failed: %w", err)
	}
	return nil
}

// GroupExists checks whether a Linux group exists.
func (m *UserManager) GroupExists(groupName string) (bool, error) {
	if err := validateGroupName(groupName); err != nil {
		return false, err
	}
	_, err := runCmd("getent", "group", groupName)
	if err != nil {
		return false, nil
	}
	return true, nil
}

// AddUserToGroup adds a user to a Linux group.
func (m *UserManager) AddUserToGroup(username, groupName string) error {
	if err := validateUsername(username); err != nil {
		return err
	}
	if err := validateGroupName(groupName); err != nil {
		return err
	}
	// usermod -aG <group> <user>
	// -a: append (don't remove from other groups)
	// -G: supplementary groups
	_, err := runCmd("usermod", "-aG", groupName, username)
	if err != nil {
		return fmt.Errorf("usermod add group failed: %w", err)
	}
	return nil
}

// RemoveUserFromGroup removes a user from a Linux group.
func (m *UserManager) RemoveUserFromGroup(username, groupName string) error {
	if err := validateUsername(username); err != nil {
		return err
	}
	if err := validateGroupName(groupName); err != nil {
		return err
	}
	// gpasswd -d <user> <group>
	_, err := runCmd("gpasswd", "-d", username, groupName)
	if err != nil {
		return fmt.Errorf("gpasswd remove failed: %w", err)
	}
	return nil
}

// ─── Service Operations ───────────────────────────────────────────────────────

// RestartSamba restarts the smbd and nmbd services.
func (m *UserManager) RestartSamba() error {
	// Try systemctl first (systemd systems)
	if _, err := runCmd("systemctl", "restart", "smbd"); err != nil {
		// Fallback to service command (older systems)
		if _, err2 := runCmd("service", "smbd", "restart"); err2 != nil {
			return fmt.Errorf("restart smbd failed (systemctl: %v, service: %v)", err, err2)
		}
	}
	// nmbd for NetBIOS name resolution (best-effort)
	_, _ = runCmd("systemctl", "restart", "nmbd")
	return nil
}

// TestSambaConfig runs testparm to validate smb.conf.
// Returns the testparm output on both success and failure.
func (m *UserManager) TestSambaConfig(confPath string) (string, error) {
	// testparm -s <configfile>
	// -s: suppress prompt, just check and exit
	out, err := runCmd("testparm", "-s", confPath)
	return out, err
}

// ─── Directory Operations ─────────────────────────────────────────────────────

// SetDirectoryOwnership sets the owner and group of a directory.
// Only absolute paths are accepted to prevent path traversal.
func (m *UserManager) SetDirectoryOwnership(path, owner, group string) error {
	if err := validateAbsPath(path); err != nil {
		return err
	}
	if owner != "" {
		if err := validateUsername(owner); err != nil {
			return err
		}
	}
	if group != "" {
		if err := validateGroupName(group); err != nil {
			return err
		}
	}

	ownerSpec := owner + ":" + group
	_, err := runCmd("chown", ownerSpec, path)
	if err != nil {
		return fmt.Errorf("chown failed: %w", err)
	}
	return nil
}

// MakeDirectory creates a directory with specific permissions.
func (m *UserManager) MakeDirectory(path, mode string) error {
	if err := validateAbsPath(path); err != nil {
		return err
	}
	if !regexp.MustCompile(`^0[0-7]{3}$`).MatchString(mode) {
		return errors.New("mode must be an octal string like 0755")
	}
	_, err := runCmd("mkdir", "-p", "-m", mode, path)
	if err != nil {
		return fmt.Errorf("mkdir failed: %w", err)
	}
	return nil
}

// ─── Validation helpers ───────────────────────────────────────────────────────

func validateUsername(s string) error {
	if !reUsername.MatchString(s) {
		return fmt.Errorf("invalid username %q: must match ^[a-z_][a-z0-9_-]{0,30}$", s)
	}
	return nil
}

func validateGroupName(s string) error {
	if !reGroupName.MatchString(s) {
		return fmt.Errorf("invalid group name %q: must match ^[a-z_][a-z0-9_-]{0,30}$", s)
	}
	return nil
}

func validatePassword(s string) error {
	if !utf8.ValidString(s) {
		return errors.New("password contains invalid UTF-8 sequences")
	}
	if !rePassword.MatchString(s) {
		return errors.New("password must be 8-128 characters long")
	}
	return nil
}

func validateAbsPath(p string) error {
	if !strings.HasPrefix(p, "/") {
		return fmt.Errorf("path must be absolute: %q", p)
	}
	// Prevent directory traversal
	if strings.Contains(p, "..") {
		return fmt.Errorf("path must not contain '..': %q", p)
	}
	// Deny null bytes
	if strings.ContainsRune(p, 0) {
		return fmt.Errorf("path must not contain null bytes")
	}
	return nil
}

// ─── Command execution helpers ────────────────────────────────────────────────

// runCmd executes a command with explicit arguments — never via shell.
// This is the ONLY place subprocess execution happens in this package.
func runCmd(name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), execTimeout)
	defer cancel()

	//nolint:gosec // arguments are validated before this call
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		combined := strings.TrimSpace(stderr.String())
		if combined == "" {
			combined = err.Error()
		}
		return "", fmt.Errorf("%s: %s", name, combined)
	}
	return strings.TrimSpace(stdout.String()), nil
}

// runCmdWithStdin is like runCmd but also writes data to the process's stdin.
// Used for smbpasswd which reads the password from stdin.
func runCmdWithStdin(stdin, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), execTimeout)
	defer cancel()

	//nolint:gosec // arguments are validated before this call
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	if err := cmd.Run(); err != nil {
		combined := strings.TrimSpace(stderr.String())
		if combined == "" {
			combined = err.Error()
		}
		return "", fmt.Errorf("%s: %s", name, combined)
	}
	return strings.TrimSpace(stdout.String()), nil
}
