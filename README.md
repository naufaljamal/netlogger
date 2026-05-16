# NetLogger

NetLogger is an open-source tool for network engineers to SSH into network devices directly from a browser, capture full session activity, and automatically commit logs to a GitLab repository. It supports multiple concurrent sessions, secret redaction, and automatic log commits triggered by time intervals or configuration save commands.

---

## Features

- **Browser-based SSH terminal** — Connect to network devices from any browser using xterm.js. No local SSH client required.
- **Multi-session tabs** — Open multiple device sessions simultaneously, each in its own tab named after the device.
- **Automatic log commits** — Session output is committed to GitLab every 5 minutes and immediately when a `write mem` (or equivalent) command is detected.
- **Secret redaction** — Passwords, SNMP community strings, keys, and other secrets are automatically redacted before logs are stored.
- **Log viewer** — Browse and search historical session logs by date range directly from the UI.
- **Light/dark theme** — Toggle between light and dark terminal themes, saved to browser local storage.
- **CLI mode** — Connect to a device directly from the terminal without the web UI.

---

## How It Works

1. Engineer opens the NetLogger web UI and enters a device hostname, username, and password.
2. NetLogger establishes an SSH connection to the device via a server-side PTY (pseudo-terminal).
3. All terminal input and output is streamed to the browser over WebSocket using xterm.js.
4. Session output is buffered on the server, stripped of ANSI escape codes, and redacted of secrets.
5. Logs are committed to a GitLab repository automatically every 5 minutes, on `write mem`, or when the session ends.

---

## Requirements

- Go 1.22 or later (for building from source)
- Docker (for containerised deployment)
- A GitLab account with a personal access token that has `api` scope
- A GitLab project to store logs in

---

## Configuration

NetLogger is configured entirely through environment variables — no config files, no hardcoded values.

| Variable | Required | Default | Description |
|---|---|---|---|
| `GITLAB_TOKEN` | Yes | — | GitLab personal access token with `api` scope |
| `GITLAB_PROJECT_ID` | Yes | — | Numeric ID of the GitLab project to commit logs to |
| `GITLAB_API_URL` | No | `https://gitlab.com/api/v4` | GitLab API base URL (change for self-hosted instances) |

### Finding your GitLab Project ID

Go to your GitLab project → **Settings → General**. The project ID is shown at the top of the page.

### Creating a GitLab Personal Access Token

Go to **GitLab → User Settings → Access Tokens**, create a token with the `api` scope, and copy the value.

---

## Running with Docker (Recommended)

### Pull and run

```bash
docker run -d \
  -e GITLAB_TOKEN=your-personal-access-token \
  -e GITLAB_PROJECT_ID=123456 \
  -p 8080:8080 \
  --name netlogger \
  netlogger:latest
```

For a self-hosted GitLab instance:

```bash
docker run -d \
  -e GITLAB_TOKEN=your-personal-access-token \
  -e GITLAB_PROJECT_ID=123456 \
  -e GITLAB_API_URL=https://gitlab.example.com/api/v4 \
  -p 8080:8080 \
  --name netlogger \
  netlogger:latest
```

Then open `http://localhost:8080` in your browser.

### Build the image yourself

```bash
go mod vendor
docker build -t netlogger .
docker run -d \
  -e GITLAB_TOKEN=your-token \
  -e GITLAB_PROJECT_ID=123456 \
  -p 8080:8080 \
  --name netlogger \
  netlogger:latest
```

### Useful Docker commands

```bash
# View logs
docker logs -f netlogger

# Stop
docker stop netlogger

# Restart
docker start netlogger

# Remove and re-run with updated image
docker rm -f netlogger
docker run ...
```

---

## Building from Source

```bash
git clone https://github.com/your-org/netlogger.git
cd netlogger

go mod download
go build -o netlogger .
```

### Run the web server

```bash
export GITLAB_TOKEN=your-token
export GITLAB_PROJECT_ID=123456
./netlogger --serve
```

Open `http://localhost:8080`.

### Run in CLI mode

CLI mode connects directly to a device without the web UI and captures the session to GitLab.

```bash
export GITLAB_TOKEN=your-token
export GITLAB_PROJECT_ID=123456
./netlogger --connect spine01.example.com
```

You will be prompted for your username, password, and a commit message.

### Available flags

| Flag | Description | Default |
|---|---|---|
| `--serve` | Start the web UI server | — |
| `--addr` | Web server listen address | `:8080` |
| `--connect / -c` | Device hostname for CLI mode | — |

---

## Log Storage Structure

Logs are committed to GitLab under the following path structure:

```
logs/
  YYYY-MM-DD/
    device-hostname/
      device-hostname-YYYYMMDDTHHmmss-username.log.txt
```

Example:

```
logs/
  2026-04-25/
    spine01/
      spine01-20260425T143022-jsmith.log.txt
    leaf02/
      leaf02-20260425T151800-alopez.log.txt
```

Each file contains the full terminal session output with ANSI escape codes removed and secrets redacted.

---

## Secret Redaction

The following patterns are automatically redacted before logs are written:

| Pattern | Example |
|---|---|
| SNMP community strings | `snmp-server community <REDACTED>` |
| Passwords | `password <REDACTED>` |
| Enable secrets | `enable secret <REDACTED>` |
| BGP neighbor passwords | `neighbor 10.0.0.1 password <REDACTED>` |
| Key strings | `key-string <REDACTED>` |
| TACACS keys | `tacacs-server key <REDACTED>` |
| RADIUS keys | `radius-server key <REDACTED>` |
| IKE pre-shared keys | `pre-shared-key <REDACTED>` |
| NTP authentication keys | `ntp authentication-key 1 md5 <REDACTED>` |

---

## Automatic Commit Triggers

Sessions are committed to GitLab automatically in three situations:

1. **Every 5 minutes** — while the session is active
2. **On `write mem`** — any of the following commands trigger an immediate commit:
   - `write mem`
   - `write memory`
   - `wr mem`
   - `wr m`
   - `wr memory`
3. **On session exit** — when the engineer clicks Exit or closes the tab

---

## Supported Platforms

NetLogger connects over standard SSH and works with any device that accepts SSH connections, including:

- Cisco IOS / IOS-XE / NX-OS
- Arista EOS
- Cumulus Linux
- Juniper JunOS
- Any Linux host

---

## Architecture

```
Browser (xterm.js)
       │  WebSocket (/ws)
       ▼
  Go HTTP Server
       │  PTY (pseudo-terminal)
       ▼
  SSH → Network Device
       │
       ▼
  Log buffer → ANSI strip → Secret redact → GitLab Files API
```

- **WebSocket handler** (`server.go`) manages the browser ↔ PTY lifecycle per session
- **Session struct** (`netcli.go`) holds per-session state: log buffer, GitLab file state, commit mutex
- **PTY** provides a real terminal so interactive prompts (passwords, pagers) work correctly
- **GitLab Files API** is used to POST (create) or PUT (update) log files as sessions progress

---

## Contributing

Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

---

## License

MIT
