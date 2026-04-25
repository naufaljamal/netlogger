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

var (
	gitlabToken string
	projectID   string
	gitlabAPI   string
)

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

var ansiRe = regexp.MustCompile(`\x1b\[[0-9;]*[a-zA-Z]`)

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
	username := s.username
	if username == "" {
		if u, err := user.Current(); err == nil {
			username = u.Username
		}
	}
	now := time.Now().UTC()
	logDir := fmt.Sprintf("logs/%s/%s", now.Format("2006-01-02"), s.device)
	os.MkdirAll(logDir, 0755)
	s.logFilePath = fmt.Sprintf("%s/%s-%s-%s.log.txt", logDir, s.device, now.Format("20060102T150405"), username)
}

func (s *Session) commitLog(msg string) {
	s.commitMu.Lock()
	defer s.commitMu.Unlock()

	s.rawBufMu.Lock()
	raw := s.rawBuf.String()
	s.rawBufMu.Unlock()

	f, err := os.Create(s.logFilePath)
	if err != nil {
		log.Printf("❌ Failed to write log: %v\n", err)
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
	s.uploadToGitlab(msg)
}

func (s *Session) doGitlabRequest(method, apiURL string, payload map[string]string) (int, []byte, error) {
	body, _ := json.Marshal(payload)
	req, _ := http.NewRequest(method, apiURL, bytes.NewBuffer(body))
	req.Header.Set("PRIVATE-TOKEN", gitlabToken)
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
	content, err := os.ReadFile(s.logFilePath)
	if err != nil {
		log.Printf("❌ Error reading log file: %v\n", err)
		return
	}

	encodedPath := url.PathEscape(s.logFilePath)
	apiURL := fmt.Sprintf("%s/projects/%s/repository/files/%s", gitlabAPI, projectID, encodedPath)
	payload := map[string]string{
		"branch": "main", "content": string(content),
		"commit_message": commitMsg, "encoding": "text",
	}

	method := "POST"
	if s.gitlabFileCreated {
		method = "PUT"
	}
	status, respBody, err := s.doGitlabRequest(method, apiURL, payload)
	if err != nil {
		log.Printf("❌ GitLab commit failed: %v\n", err)
		return
	}
	switch {
	case status == 200 || status == 201:
		s.gitlabFileCreated = true
		log.Println("✅ GitLab commit successful")
	case status == 400 && bytes.Contains(respBody, []byte("already exists")):
		s.gitlabFileCreated = true
		status2, _, err2 := s.doGitlabRequest("PUT", apiURL, payload)
		if err2 == nil && (status2 == 200 || status2 == 201) {
			log.Println("✅ GitLab commit successful")
		} else {
			log.Printf("❌ GitLab commit failed on PUT retry: HTTP %d\n", status2)
		}
	default:
		log.Printf("❌ GitLab commit failed: HTTP %d\nResponse: %s\n", status, string(respBody))
	}
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
	case "write mem", "write memory", "wr mem", "wr m", "wr memory":
		return true
	}
	return false
}

// stdinInterceptor forwards keystrokes to the PTY and detects write mem commands.
type stdinInterceptor struct {
	dst        io.Writer
	buf        bytes.Buffer
	inEsc      bool
	onWriteMem func()
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
	cmd := exec.Command("ssh", fmt.Sprintf("%s@%s", s.username, s.device))
	ptmx, err := pty.Start(cmd)
	if err != nil {
		log.Fatalf("❌ Failed to start PTY: %v", err)
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
		log.Fatalf("❌ Failed to set raw mode: %v", err)
	}

	go io.Copy(&stdinInterceptor{
		dst: ptmx,
		onWriteMem: func() {
			s.commitLog(fmt.Sprintf("netlogger: [%s] auto-commit (write mem)", s.device))
		},
	}, os.Stdin)

	go func() {
		buf := make([]byte, 4096)
		for {
			n, err := ptmx.Read(buf)
			if n > 0 {
				os.Stdout.Write(buf[:n])
				s.rawBufMu.Lock()
				s.rawBuf.Write(buf[:n])
				s.rawBufMu.Unlock()
			}
			if err != nil {
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
				s.commitLog(fmt.Sprintf("netlogger: [%s] auto-commit (5-min interval)", s.device))
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

var (
	app       = kingpin.New("netlogger", "A CLI tool to interact with network devices.")
	connect   = app.Flag("connect", "Device hostname to connect to (CLI mode)").Short('c').String()
	gitCommit = app.Flag("git_commit", "Trigger a test GitLab commit").Bool()
	serve     = app.Flag("serve", "Start the web UI server").Bool()
	serveAddr = app.Flag("addr", "Web server listen address").Default(":8080").String()
)

func main() {
	kingpin.MustParse(app.Parse(os.Args[1:]))

	gitlabToken = os.Getenv("GITLAB_TOKEN")
	if gitlabToken == "" {
		log.Fatal("GITLAB_TOKEN environment variable is required")
	}
	projectID = os.Getenv("GITLAB_PROJECT_ID")
	if projectID == "" {
		log.Fatal("GITLAB_PROJECT_ID environment variable is required")
	}
	gitlabAPI = os.Getenv("GITLAB_API_URL")
	if gitlabAPI == "" {
		gitlabAPI = "https://gitlab.com/api/v4"
	}

	if *serve {
		startServer(*serveAddr)
		return
	}

	if *gitCommit {
		if *connect == "" {
			log.Fatal("--connect required for --git_commit")
		}
		s := newSession(*connect, "test", "test commit")
		s.rawBufMu.Lock()
		s.rawBuf.WriteString("command: test\noutput: this is a test log\n")
		s.rawBufMu.Unlock()
		s.commitLog("test commit")
		return
	}

	if *connect == "" {
		fmt.Fprintln(os.Stderr, "usage: netlogger --connect <device>  or  netlogger --serve")
		os.Exit(1)
	}

	var username, password, commitMsg string
	survey.AskOne(&survey.Input{Message: "Username:"}, &username)
	survey.AskOne(&survey.Password{Message: "Password:"}, &password)
	survey.AskOne(&survey.Input{Message: "Commit message:"}, &commitMsg)
	_ = password

	newSession(*connect, username, commitMsg).runCLI()
}
