<div align="center">

# SambaGuard

### Control, Secure, Monitor — All in One.

A production-grade, open-source Samba Server Management Panel with a modern Web GUI.

[![Go](https://img.shields.io/badge/Go-1.21+-00ADD8?style=flat&logo=go)](https://go.dev)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Docker](https://img.shields.io/badge/Docker-ready-2496ED?style=flat&logo=docker)](Dockerfile)
[![Security](https://img.shields.io/badge/Security-hardened-red?style=flat&logo=shieldsdotio)](docs/SECURITY.md)

![SambaGuard Dashboard](docs/screenshots/placeholder.png)

</div>

---

## What is SambaGuard?

SambaGuard is a secure, **self-hosted web panel** for managing Samba file servers on Linux. It replaces manual `smb.conf` editing and `smbpasswd` commands with a clean browser-based interface — while keeping security as the top priority.

Built entirely in **Go** with zero CGO dependencies. The single static binary embeds all frontend assets, making deployment trivial.

---

## Features

| | Feature |
|---|---|
| 👥 | **Samba User Management** — Create, disable, delete users with no shell/SSH access |
| 🗂 | **Group Management** — Linux groups mapped to Samba ACLs |
| 📁 | **Share Management** — GUI-based permission assignment, smb.conf auto-generated |
| ⚙️ | **Config Lifecycle** — Stage → Validate → Apply atomically → Restart Samba |
| 🔐 | **Hardened Auth** — JWT + bcrypt + account lockout + CSRF + rate limiting |
| 📜 | **Full Audit Log** — Who did what, when, from which IP |
| 🕐 | **Config History** — Version snapshots, backup/restore |
| 📡 | **Real-time UI** — Server-Sent Events for live notifications |
| 🐳 | **Docker Ready** — Single `docker compose up -d` deployment |
| 🔑 | **RBAC** — Admin / Operator / Viewer roles |

---

## Screenshots

> _Screenshots will be added after the first stable release._

---

## Quick Start

### Docker (Recommended)

```bash
git clone https://github.com/buadamlaz/SambaGuard.git
cd SambaGuard

# Auto-generate secrets and create .env
make setup-env

# Start
docker compose up -d

# First-run: retrieve the auto-generated admin credentials
docker compose logs sambaguard | grep -A8 "FIRST RUN\|SAMBAGUARD"
```

On first run, you will see a box like this in the logs:

```
╔══════════════════════════════════════════════════════╗
║          SAMBAGUARD — FIRST RUN CREDENTIALS          ║
╠══════════════════════════════════════════════════════╣
║  Username : admin                                    ║
║  Password : xK9mP2vQ8nR4...                         ║
╠══════════════════════════════════════════════════════╣
║  ⚠  Change this password immediately after login!   ║
╚══════════════════════════════════════════════════════╝
```

> **Note:** Leave `INIT_ADMIN_PASS` empty in `.env` to auto-generate a secure random password.
> The credentials box is only shown once — on the very first startup when the database is empty.

Open **http://your-server:8090** and sign in.

### Build from Source

**Requirements:** Go 1.21+, Linux (Debian/Ubuntu), Samba

```bash
git clone https://github.com/buadamlaz/SambaGuard.git
cd SambaGuard

# Download dependencies
go mod download

# Setup environment
make setup-env        # Creates .env with auto-generated secrets
nano .env             # Review / customise

# Build Linux binary
make build            # → bin/sambaguard

# Run (needs root or CAP_SYS_ADMIN to manage OS users)
sudo -E ./bin/sambaguard
```

---

## Project Structure

```
sambaguard/
├── cmd/server/           ← Entry point (main.go)
├── internal/
│   ├── config/           ← Environment-based configuration
│   ├── database/         ← SQLite + embedded schema migrations
│   ├── model/            ← Data models and DTOs
│   ├── repository/       ← Data access layer (users, groups, shares, audit)
│   ├── service/          ← Business logic (auth, users, Samba config)
│   ├── handler/          ← HTTP handlers + chi router
│   └── middleware/       ← Auth, CSRF, rate limiter, security headers
├── pkg/
│   ├── system/           ← Safe Linux user/group/service management
│   └── samba/            ← smb.conf parser, builder, atomic write
├── web/
│   ├── templates/        ← index.html (SPA shell)
│   └── static/js/        ← Alpine.js frontend (app.js)
├── scripts/              ← Docker entrypoint, setup helpers
├── Dockerfile
├── docker-compose.yml
├── Makefile
└── .env.example
```

---

## Architecture

```
Browser (Alpine.js + Tailwind)
    │  JWT in memory · Refresh token in httpOnly cookie · CSRF header
    ▼
Handler Layer  (chi router + middleware stack)
    │  Auth · CSRF · Rate limit · Security headers · Request logging
    ▼
Service Layer  (business logic + orchestration)
    │  Validation · Audit emission · OS ↔ DB coordination
    ├──────────────────────┐
    ▼                      ▼
Repository Layer      System Package
(SQLite)              pkg/system — safe subprocess calls
                      pkg/samba  — smb.conf builder
```

---

## Security Design

### Authentication Flow
- **Access token** (15 min): JWT stored in JS memory — never `localStorage` or cookies
- **Refresh token** (7 days): stored in `httpOnly; Secure; SameSite=Strict` cookie — invisible to JavaScript
- **Token rotation**: every refresh issues a new pair; old token is immediately revoked
- **Server-side storage**: SHA-256 hash of each refresh token stored in DB for revocation

### CSRF Protection
Double-submit cookie pattern — attacker from a foreign origin cannot read the cookie, therefore cannot forge the header.

### No Command Injection
Every subprocess call uses an explicit argument list — never `sh -c` + user input:
```go
// ✅ Safe — exec.Command with explicit args
exec.Command("useradd", "-r", "-s", "/usr/sbin/nologin", "-M", username)

// ❌ Never done — shell interpolation
exec.Command("sh", "-c", "useradd " + username)
```

### Samba User Isolation
Every user created through SambaGuard has:
- Shell: `/usr/sbin/nologin` → **no interactive login**
- No home directory (`-M`) → **no SSH key placement**  
- System account (`-r`) → **restricted UID range**

### HTTP Security Headers
`X-Content-Type-Options`, `X-Frame-Options: DENY`, `Content-Security-Policy` (strict), `Referrer-Policy`, `Permissions-Policy`

---

## Configuration

Copy `.env.example` to `.env` and fill in the required values:

```bash
# Required — generate with: openssl rand -hex 32
JWT_SECRET=<min 32 chars>
CSRF_SECRET=<min 32 chars>
```

| Variable | Default | Description |
|---|---|---|
| `JWT_SECRET` | **required** | JWT signing secret (≥32 chars) |
| `CSRF_SECRET` | **required** | CSRF token secret (≥32 chars) |
| `PORT` | `8090` | HTTP listen port |
| `ENVIRONMENT` | `production` | `development` or `production` |
| `DATABASE_PATH` | `/var/lib/sambaguard/panel.db` | SQLite path |
| `SMB_CONF_PATH` | `/etc/samba/smb.conf` | Live smb.conf path |
| `BCRYPT_COST` | `12` | bcrypt work factor (10–14) |
| `RATE_LIMIT_LOGIN_ATTEMPTS` | `5` | Failures before lockout |
| `RATE_LIMIT_WINDOW_SECONDS` | `900` | Lockout window (15 min) |
| `LOG_LEVEL` | `info` | `debug` / `info` / `warn` / `error` |
| `INIT_ADMIN_USER` | `admin` | Bootstrap admin username |
| `INIT_ADMIN_PASS` | _(auto)_ | Leave empty to auto-generate |
| `TLS_CERT_FILE` | — | TLS certificate path |
| `TLS_KEY_FILE` | — | TLS private key path |

---

## API Reference

All endpoints are under `/api/v1/`. Protected endpoints require `Authorization: Bearer <token>`.

### Auth
```
POST   /api/v1/auth/login         Sign in → access token + refresh cookie
POST   /api/v1/auth/refresh       Rotate tokens (uses httpOnly cookie)
POST   /api/v1/auth/logout        Revoke tokens + clear cookies
GET    /api/v1/auth/me            Current user info
POST   /api/v1/auth/csrf          Issue CSRF token
```

### Samba Users _(operator+ role)_
```
GET    /api/v1/users              List  ?search=&status=&limit=&offset=
POST   /api/v1/users              Create
GET    /api/v1/users/:id          Get
PUT    /api/v1/users/:id          Update (status / display_name / comment)
DELETE /api/v1/users/:id          Delete
POST   /api/v1/users/:id/password Change Samba password
```

### Groups _(operator+ role)_
```
GET    /api/v1/groups             List
POST   /api/v1/groups             Create
GET    /api/v1/groups/:id         Get
DELETE /api/v1/groups/:id         Delete
POST   /api/v1/groups/:id/members/:userId   Add member
DELETE /api/v1/groups/:id/members/:userId   Remove member
```

### Shares _(operator+ role)_
```
GET    /api/v1/shares             List
POST   /api/v1/shares             Create
GET    /api/v1/shares/:id         Get
PUT    /api/v1/shares/:id         Update (comment / ACL / flags)
DELETE /api/v1/shares/:id         Delete
```

### Configuration
```
GET    /api/v1/config/status      Pending changes flag + timestamps
POST   /api/v1/config/apply       Validate → apply → restart Samba  [admin]
POST   /api/v1/config/backup      Create named backup               [admin]
GET    /api/v1/config/backups     List backups
GET    /api/v1/config/versions    Version history
GET    /api/v1/config/versions/:id Config content at that version
```

### Audit & Stats
```
GET    /api/v1/logs               Audit log  ?search=&action=&limit=&offset=
GET    /api/v1/logs/stats         Dashboard counters
```

### Real-time
```
GET    /api/v1/events             Server-Sent Events (pings + config change notifications)
```

---

## Example: Creating a Share with ACL

```bash
# 1. Login
TOKEN=$(curl -s -c cookies.txt -X POST http://localhost:8090/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"username":"admin","password":"YOUR_PASSWORD"}' | jq -r .access_token)

CSRF=$(curl -s -b cookies.txt http://localhost:8090/api/v1/auth/csrf \
  | jq -r .csrf_token)

# 2. Create share
curl -s -X POST http://localhost:8090/api/v1/shares \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-CSRF-Token: $CSRF" \
  -H 'Content-Type: application/json' \
  -d '{
    "name": "projects",
    "path": "/srv/samba/projects",
    "comment": "Engineering project files",
    "browseable": true,
    "read_only": false,
    "owner_group": "developers",
    "create_mask": "0664",
    "dir_mask": "0775",
    "acl": [
      {"principal": "@developers", "permission": "read_write"},
      {"principal": "@management", "permission": "read_only"}
    ]
  }' | jq .

# 3. Apply (validate + write smb.conf + restart Samba)
curl -s -X POST http://localhost:8090/api/v1/config/apply \
  -H "Authorization: Bearer $TOKEN" \
  -H "X-CSRF-Token: $CSRF" | jq .
```

---

## Generated smb.conf Example

```ini
# Managed by SambaGuard — do not edit manually
# Generated at: 2024-06-01T12:00:00Z

[global]
   workgroup                      = WORKGROUP
   server string                  = Samba Server
   server role                    = standalone server
   security                       = user
   map to guest                   = Bad User
   usershare allow guests         = no
   obey pam restrictions          = yes
   unix password sync             = no

[projects]
   path                           = /srv/samba/projects
   comment                        = Engineering project files
   browseable                     = yes
   read only                      = no
   guest ok                       = no
   create mask                    = 0664
   directory mask                 = 0775
   valid users                    = @developers @management
   write list                     = @developers
```

---

## Production Checklist

- [ ] Set strong `JWT_SECRET` and `CSRF_SECRET` (≥32 random chars each)
- [ ] Enable TLS or place behind a reverse proxy (nginx/Traefik) with HTTPS
- [ ] Set `ENVIRONMENT=production`
- [ ] Change default admin password immediately after first login
- [ ] Mount `/var/lib/sambaguard` on a persistent volume
- [ ] Configure log rotation for `/var/log/sambaguard/audit.log`
- [ ] Restrict firewall: port 8090 (panel), 445 (SMB), 139 (NetBIOS)

---

## Make Targets

```
make build           Build Linux binary (deployment target)
make build-local     Build for current OS (local testing)
make run             Run in development mode
make test            Run tests with race detector
make test-coverage   Generate HTML coverage report
make lint            Run golangci-lint
make fmt             Format source code
make vet             Run go vet
make tidy            Tidy and verify go modules
make setup-env       Create .env with auto-generated secrets
make generate-secrets Print new random secrets to stdout
make docker          Build Docker image
make docker-run      Start with docker-compose
make docker-stop     Stop docker-compose stack
make docker-logs     Follow container logs
make clean           Remove build artifacts
```

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/your-feature`)
3. Commit your changes (`git commit -m 'Add your feature'`)
4. Push to the branch (`git push origin feature/your-feature`)
5. Open a Pull Request

Please ensure `make vet` and `make test` pass before submitting.

---

## License

[MIT License](LICENSE) — free to use, modify, and distribute.

---

<div align="center">

**SambaGuard** — Control, Secure, Monitor — All in One.

</div>
