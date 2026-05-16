package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/AlecAivazis/survey/v2"
	"github.com/alecthomas/kingpin/v2"
	"github.com/creack/pty"
	"golang.org/x/term"
)

// ── Global config (populated from flags / env vars in main) ──────────────────

var cfg struct {
	gitlabToken     string
	gitlabProjectID string
	gitlabAPIURL    string
}

// ── Shared: ANSI / secret redaction ──────────────────────────────────────────

// ansiRe strips CSI sequences (ESC [ ... letter), OSC sequences (ESC ] ... BEL/ST),
// and other two-character ESC sequences.
var ansiRe = regexp.MustCompile(`\x1b(?:\[[0-9;?]*[a-zA-Z]|\][^\x07\x1b]*\x07|\][^\x1b]*\x1b\\|[0-9A-Za-z=><])`)

var redactPatterns = []*regexp.Regexp{
	regexp.MustCompile(`(?i)(snmp(?:-server)?\s+community\s+)\S+`),
	regexp.MustCompile(`(?i)(password\s+)(?:[0-9]\s+)?\S+`),
	regexp.MustCompile(`(?i)(secret\s+)(?:[0-9]\s+)?\S+`),
	regexp.MustCompile(`(?i)(enable\s+(?:secret|password)\s+)(?:[0-9]\s+)?\S+`),
	regexp.MustCompile(`(?i)(neighbor\s+\S+\s+password\s+)\S+`),
	regexp.MustCompile(`(?i)(key-string\s+)\S+`),
	regexp.MustCompile(`(?i)(tacacs(?:-server)?\s+key\s+)\S+`),
	regexp.MustCompile(`(?i)(radius(?:-server)?\s+key\s+)\S+`),
	regexp.MustCompile(`(?i)(pre-shared-key\s+(?:local\s+|remote\s+)?)\S+`),
	regexp.MustCompile(`(?i)(ntp\s+authentication-key\s+\d+\s+\S+\s+)\S+`),
	regexp.MustCompile(`(?i)(authentication-key\s+)\S+`),
}

func stripAnsi(s string) string { return ansiRe.ReplaceAllString(s, "") }

func redactSecrets(line string) string {
	for _, re := range redactPatterns {
		line = re.ReplaceAllString(line, "${1}<REDACTED>")
	}
	return line
}

func isWriteMemCmd(cmd string) bool {
	switch cmd {
	case "write mem", "write memory", "wr mem", "wr m", "wr memory",
		"copy run start", "copy running-config startup-config":
		return true
	}
	return false
}

func isQuitCmd(cmd string) bool {
	switch cmd {
	case "exit", "quit", "logout", "q", "bye":
		return true
	}
	return false
}

// ── Session ───────────────────────────────────────────────────────────────────

// Session holds all state for one device connection (CLI or web).
type Session struct {
	device        string
	username      string
	commitMessage string
	logFilePath   string

	gitlabFileCreated bool
	rawBuf            bytes.Buffer
	rawBufMu          sync.Mutex
	commitMu          sync.Mutex
}

func newSession(device, username, commitMsg string) *Session {
	s := &Session{device: device, username: username, commitMessage: commitMsg}
	s.initLogFile()
	return s
}

func (s *Session) initLogFile() {
	uname := s.username
	if uname == "" {
		if u, err := user.Current(); err == nil {
			uname = u.Username
		} else {
			uname = "unknown"
		}
	}
	now := time.Now().UTC()
	logDir := filepath.Join("logs", now.Format("2006-01-02"), s.device)
	os.MkdirAll(logDir, 0755)
	s.logFilePath = filepath.Join(logDir,
		fmt.Sprintf("%s-%s-%s.log.txt", s.device, now.Format("20060102T150405Z"), uname))
}

func (s *Session) commitLog(msg string) {
	s.commitMu.Lock()
	defer s.commitMu.Unlock()

	s.rawBufMu.Lock()
	raw := s.rawBuf.String()
	s.rawBufMu.Unlock()

	f, err := os.Create(s.logFilePath)
	if err != nil {
		log.Printf("failed to write log: %v", err)
		return
	}
	for _, line := range strings.Split(stripAnsi(raw), "\n") {
		line = strings.TrimRight(line, "\r")
		line = redactSecrets(line)
		if line != "" {
			fmt.Fprintln(f, line)
		}
	}
	f.Close()
	log.Printf("log saved: %s", s.logFilePath)

	if cfg.gitlabToken != "" {
		s.uploadToGitlab(msg)
	}
}

// ── GitLab upload ─────────────────────────────────────────────────────────────

func (s *Session) doGitlabRequest(method, apiURL string, payload map[string]string) (int, []byte, error) {
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest(method, apiURL, bytes.NewBuffer(body))
	req.Header.Set("PRIVATE-TOKEN", cfg.gitlabToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return 0, nil, err
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, respBody, nil
}

func (s *Session) uploadToGitlab(commitMsg string) {
	if cfg.gitlabToken == "" || cfg.gitlabProjectID == "" {
		return
	}

	content, err := os.ReadFile(s.logFilePath)
	if err != nil {
		log.Printf("gitlab upload: error reading log: %v", err)
		return
	}

	encodedPath := url.PathEscape(s.logFilePath)
	apiURL := fmt.Sprintf("%s/projects/%s/repository/files/%s", cfg.gitlabAPIURL, cfg.gitlabProjectID, encodedPath)
	payload := map[string]string{
		"branch":         "main",
		"content":        string(content),
		"commit_message": commitMsg,
		"encoding":       "text",
	}

	method := "POST"
	if s.gitlabFileCreated {
		method = "PUT"
	}
	status, respBody, err := s.doGitlabRequest(method, apiURL, payload)
	if err != nil {
		log.Printf("gitlab upload error: %v", err)
		return
	}
	switch {
	case status == 200 || status == 201:
		s.gitlabFileCreated = true
		log.Println("gitlab: commit successful")
	case status == 400 && bytes.Contains(respBody, []byte("already exists")):
		s.gitlabFileCreated = true
		status2, _, err2 := s.doGitlabRequest("PUT", apiURL, payload)
		if err2 == nil && (status2 == 200 || status2 == 201) {
			log.Println("gitlab: commit successful (PUT retry)")
		} else {
			log.Printf("gitlab: PUT retry failed: HTTP %d", status2)
		}
	default:
		log.Printf("gitlab: commit failed: HTTP %d — %s", status, string(respBody))
	}
}

// ── CLI mode ──────────────────────────────────────────────────────────────────

// stdinInterceptor forwards keystrokes to the PTY and fires callbacks on
// recognised command patterns (write-mem variants, quit variants).
type stdinInterceptor struct {
	dst        io.Writer
	buf        bytes.Buffer
	inEsc      bool
	onWriteMem func()
	onQuit     func()
}

func (si *stdinInterceptor) Write(p []byte) (int, error) {
	for _, b := range p {
		switch {
		case si.inEsc:
			if (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || b == '~' {
				si.inEsc = false
			}
		case b == '\x1b':
			si.inEsc = true
		case b == '\r':
			cmd := strings.ToLower(strings.TrimSpace(si.buf.String()))
			si.buf.Reset()
			if isWriteMemCmd(cmd) {
				go si.onWriteMem()
			} else if isQuitCmd(cmd) && si.onQuit != nil {
				go si.onQuit()
			}
		case b == '\x7f' || b == '\x08':
			str := si.buf.String()
			if len(str) > 0 {
				si.buf.Reset()
				si.buf.WriteString(str[:len(str)-1])
			}
		default:
			if b >= 0x20 {
				si.buf.WriteByte(b)
			}
		}
	}
	return si.dst.Write(p)
}

func (s *Session) runCLI() {
	cmd := exec.Command("ssh",
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group1-sha1",
		"-o", "HostKeyAlgorithms=+ssh-rsa",
		"-o", "PubkeyAcceptedAlgorithms=+ssh-rsa",
		fmt.Sprintf("%s@%s", s.username, s.device),
	)
	ptmx, err := pty.Start(cmd)
	if err != nil {
		log.Fatalf("failed to start PTY: %v", err)
	}
	defer ptmx.Close()

	winch := make(chan os.Signal, 1)
	signal.Notify(winch, syscall.SIGWINCH)
	go func() {
		for range winch {
			pty.InheritSize(os.Stdin, ptmx)
		}
	}()
	winch <- syscall.SIGWINCH

	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		log.Fatalf("failed to set raw mode: %v", err)
	}

	go io.Copy(&stdinInterceptor{
		dst: ptmx,
		onWriteMem: func() {
			s.commitLog(fmt.Sprintf("netlogger: [%s] auto-commit (write mem)", s.device))
		},
		onQuit: func() {
			s.commitLog(fmt.Sprintf("netlogger: [%s] auto-commit (quit/exit)", s.device))
		},
	}, os.Stdin)

	go func() {
		buf := make([]byte, 4096)
		for {
			n, rdErr := ptmx.Read(buf)
			if n > 0 {
				os.Stdout.Write(buf[:n])
				s.rawBufMu.Lock()
				s.rawBuf.Write(buf[:n])
				s.rawBufMu.Unlock()
			}
			if rdErr != nil {
				break
			}
		}
	}()

	ticker := time.NewTicker(5 * time.Minute)
	tickerDone := make(chan struct{})
	go func() {
		for {
			select {
			case <-ticker.C:
				s.commitLog(fmt.Sprintf("netlogger: [%s] auto-commit (5-min)", s.device))
			case <-tickerDone:
				return
			}
		}
	}()

	cmd.Wait()

	ticker.Stop()
	close(tickerDone)
	signal.Stop(winch)
	close(winch)
	term.Restore(int(os.Stdin.Fd()), oldState)

	s.commitLog(s.commitMessage)
}

// ── CLI entry point ───────────────────────────────────────────────────────────

var (
	app          = kingpin.New("netlogger", "Browser-based SSH terminal with session logging.")
	connectTo    = app.Flag("connect", "Device hostname/IP to connect to (CLI mode)").Short('c').String()
	serve        = app.Flag("serve", "Start the web UI server").Bool()
	serveAddr    = app.Flag("addr", "Web server listen address").Default(":8080").String()
	gitlabToken  = app.Flag("gitlab-token", "GitLab personal access token (or set GITLAB_TOKEN env var)").String()
	gitlabProjID = app.Flag("gitlab-project-id", "GitLab project ID (or set GITLAB_PROJECT_ID env var)").String()
	gitlabAPIURL = app.Flag("gitlab-api-url", "GitLab API base URL (or set GITLAB_API_URL env var)").String()
)

func main() {
	kingpin.MustParse(app.Parse(os.Args[1:]))

	cfg.gitlabToken = *gitlabToken
	if cfg.gitlabToken == "" {
		cfg.gitlabToken = os.Getenv("GITLAB_TOKEN")
	}
	cfg.gitlabProjectID = *gitlabProjID
	if cfg.gitlabProjectID == "" {
		cfg.gitlabProjectID = os.Getenv("GITLAB_PROJECT_ID")
	}
	cfg.gitlabAPIURL = *gitlabAPIURL
	if cfg.gitlabAPIURL == "" {
		cfg.gitlabAPIURL = os.Getenv("GITLAB_API_URL")
	}
	if cfg.gitlabAPIURL == "" {
		cfg.gitlabAPIURL = "https://gitlab.com/api/v4"
	}

	// GitLab integration is optional — warn but don't require.
	if cfg.gitlabToken == "" {
		log.Println("note: --gitlab-token not set — log files will be saved locally only")
	} else if cfg.gitlabProjectID == "" {
		log.Println("note: --gitlab-project-id not set — GitLab upload disabled")
	}

	if *serve {
		startServer(*serveAddr)
		return
	}

	if *connectTo == "" {
		fmt.Fprintln(os.Stderr, "usage: netlogger --connect <device>  or  netlogger --serve")
		os.Exit(1)
	}

	var username, password, commitMsg string
	survey.AskOne(&survey.Input{Message: "Username:"}, &username)
	survey.AskOne(&survey.Password{Message: "Password:"}, &password)
	survey.AskOne(&survey.Input{Message: "Session label (commit message):"}, &commitMsg)
	_ = password // password is typed directly into the SSH PTY; we don't pass it programmatically in CLI mode

	newSession(*connectTo, username, commitMsg).runCLI()
}
