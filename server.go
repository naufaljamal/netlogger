package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

// wsMsg is the JSON envelope for all WebSocket messages.
type wsMsg struct {
	Type        string `json:"type"`
	Device      string `json:"device,omitempty"`
	Username    string `json:"username,omitempty"`
	Password    string `json:"password,omitempty"`
	SessionName string `json:"sessionName,omitempty"`
	Data        string `json:"data,omitempty"`
	Message     string `json:"message,omitempty"`
	Cols        uint16 `json:"cols,omitempty"`
	Rows        uint16 `json:"rows,omitempty"`
}

// basicAuth wraps an http.Handler with HTTP Basic Auth if NETLOGGER_PASSWORD is set.
func basicAuth(next http.Handler) http.Handler {
	password := os.Getenv("NETLOGGER_PASSWORD")
	if password == "" {
		return next
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/health" {
			next.ServeHTTP(w, r)
			return
		}
		_, pass, ok := r.BasicAuth()
		if !ok || pass != password {
			w.Header().Set("WWW-Authenticate", `Basic realm="NetLogger"`)
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// cmdTracker accumulates raw terminal input bytes and fires callbacks on
// recognised commands. Not goroutine-safe; call from one goroutine only.
type cmdTracker struct {
	buf   strings.Builder
	inEsc bool
}

func (t *cmdTracker) process(data []byte, onWriteMem func(), onQuit func()) {
	for _, b := range data {
		switch {
		case t.inEsc:
			if (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') || b == '~' {
				t.inEsc = false
			}
		case b == '\x1b':
			t.inEsc = true
		case b == '\r':
			cmd := strings.ToLower(strings.TrimSpace(t.buf.String()))
			t.buf.Reset()
			if isWriteMemCmd(cmd) {
				go onWriteMem()
			} else if isQuitCmd(cmd) {
				go onQuit()
			}
		case b == '\x7f' || b == '\x08':
			s := t.buf.String()
			if len(s) > 0 {
				t.buf.Reset()
				t.buf.WriteString(s[:len(s)-1])
			}
		default:
			if b >= 0x20 {
				t.buf.WriteByte(b)
			}
		}
	}
}

func handleWS(w http.ResponseWriter, r *http.Request) {
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Printf("ws upgrade error: %v", err)
		return
	}
	defer conn.Close()

	var (
		sess       *Session
		ptmx       *os.File
		cmd        *exec.Cmd
		connMu     sync.Mutex
		tickerDone chan struct{}
		tracker    cmdTracker
		committed  bool
	)

	send := func(msg wsMsg) {
		connMu.Lock()
		defer connMu.Unlock()
		conn.WriteJSON(msg)
	}

	defer func() {
		if tickerDone != nil {
			close(tickerDone)
		}
		if ptmx != nil {
			ptmx.Close()
		}
		if cmd != nil && cmd.Process != nil {
			cmd.Process.Kill()
			cmd.Wait()
		}
		if sess != nil && !committed {
			sess.commitLog(fmt.Sprintf("netlogger-web: [%s] session ended", sess.device))
		}
	}()

	for {
		var msg wsMsg
		if err := conn.ReadJSON(&msg); err != nil {
			break
		}

		switch msg.Type {

		case "connect":
			if ptmx != nil {
				send(wsMsg{Type: "error", Message: "already connected"})
				continue
			}
			sessionName := msg.SessionName
			if sessionName == "" {
				sessionName = fmt.Sprintf("netlogger-web: [%s] session by %s", msg.Device, msg.Username)
			}
			sess = newSession(msg.Device, msg.Username, sessionName)

			log.Printf("ws connect: %s@%s", msg.Username, msg.Device)

			cmd = exec.Command("ssh",
				"-o", "StrictHostKeyChecking=no",
				"-o", "UserKnownHostsFile=/dev/null",
				"-o", "KexAlgorithms=+diffie-hellman-group14-sha1,diffie-hellman-group1-sha1",
				"-o", "HostKeyAlgorithms=+ssh-rsa",
				"-o", "PubkeyAcceptedAlgorithms=+ssh-rsa",
				fmt.Sprintf("%s@%s", msg.Username, msg.Device),
			)
			ptmx, err = pty.Start(cmd)
			if err != nil {
				send(wsMsg{Type: "error", Message: err.Error()})
				sess, cmd = nil, nil
				continue
			}

			// Feed password into PTY after a short delay if supplied.
			if msg.Password != "" {
				go func(pw string) {
					time.Sleep(500 * time.Millisecond)
					ptmx.Write([]byte(pw + "\n"))
				}(msg.Password)
			}

			send(wsMsg{Type: "connected"})

			// PTY output → WebSocket
			go func() {
				buf := make([]byte, 4096)
				for {
					n, rdErr := ptmx.Read(buf)
					if n > 0 {
						sess.rawBufMu.Lock()
						sess.rawBuf.Write(buf[:n])
						sess.rawBufMu.Unlock()
						send(wsMsg{
							Type: "output",
							Data: base64.StdEncoding.EncodeToString(buf[:n]),
						})
					}
					if rdErr != nil {
						break
					}
				}
				send(wsMsg{Type: "disconnected"})
			}()

			// 5-minute auto-commit ticker
			tickerDone = make(chan struct{})
			go func(s *Session, done <-chan struct{}) {
				ticker := time.NewTicker(5 * time.Minute)
				defer ticker.Stop()
				for {
					select {
					case <-ticker.C:
						s.commitLog(fmt.Sprintf("netlogger-web: [%s] auto-commit (5-min)", s.device))
					case <-done:
						return
					}
				}
			}(sess, tickerDone)

		case "input":
			if ptmx == nil {
				continue
			}
			data, decErr := base64.StdEncoding.DecodeString(msg.Data)
			if decErr != nil {
				continue
			}
			if sess != nil {
				tracker.process(data,
					func() {
						sess.commitLog(fmt.Sprintf("netlogger-web: [%s] auto-commit (write mem)", sess.device))
					},
					func() {
						sess.commitLog(fmt.Sprintf("netlogger-web: [%s] auto-commit (quit/exit)", sess.device))
					},
				)
			}
			ptmx.Write(data)

		case "resize":
			if ptmx != nil && msg.Cols > 0 && msg.Rows > 0 {
				pty.Setsize(ptmx, &pty.Winsize{Rows: msg.Rows, Cols: msg.Cols})
			}

		case "exit":
			if sess != nil && !committed {
				committed = true
				label := sess.commitMessage
				if label == "" {
					label = fmt.Sprintf("netlogger-web: [%s] session by %s", sess.device, sess.username)
				}
				sess.commitLog(label)
				send(wsMsg{Type: "committed", Message: "Session committed"})
			}
			return
		}
	}
}

// handleLogsAPI returns log entries across a date range.
//
//	GET /api/logs                               → ["2026-04-24", ...]  (available dates)
//	GET /api/logs?from=2026-04-20&to=2026-04-24 → [{device,file,path,date}, ...]
func handleLogsAPI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	from := r.URL.Query().Get("from")
	to := r.URL.Query().Get("to")

	if from == "" && to == "" {
		entries, err := os.ReadDir("logs")
		if err != nil {
			json.NewEncoder(w).Encode([]string{})
			return
		}
		var dates []string
		for _, e := range entries {
			if e.IsDir() {
				dates = append(dates, e.Name())
			}
		}
		sort.Strings(dates)
		json.NewEncoder(w).Encode(dates)
		return
	}

	if from == "" {
		from = to
	}
	if to == "" {
		to = from
	}

	type FileEntry struct {
		Device string `json:"device"`
		File   string `json:"file"`
		Path   string `json:"path"`
		Date   string `json:"date"`
	}

	allDates, err := os.ReadDir("logs")
	if err != nil {
		json.NewEncoder(w).Encode([]FileEntry{})
		return
	}

	var results []FileEntry
	for _, dateDir := range allDates {
		if !dateDir.IsDir() {
			continue
		}
		date := dateDir.Name()
		if date < from || date > to {
			continue
		}
		devices, _ := os.ReadDir(filepath.Join("logs", date))
		for _, d := range devices {
			if !d.IsDir() {
				continue
			}
			files, _ := os.ReadDir(filepath.Join("logs", date, d.Name()))
			for _, f := range files {
				if !f.IsDir() {
					results = append(results, FileEntry{
						Device: d.Name(),
						File:   f.Name(),
						Path:   filepath.Join(date, d.Name(), f.Name()),
						Date:   date,
					})
				}
			}
		}
	}
	json.NewEncoder(w).Encode(results)
}

// handleLogFile returns the content of a specific log file.
// GET /api/logs/file?path=2026-04-24/spine01/spine01-....log.txt
func handleLogFile(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Query().Get("path")
	if path == "" || strings.Contains(path, "..") {
		http.Error(w, "invalid path", http.StatusBadRequest)
		return
	}
	content, err := os.ReadFile(filepath.Join("logs", path))
	if err != nil {
		http.Error(w, "file not found", http.StatusNotFound)
		return
	}
	w.Header().Set("Content-Type", "text/plain; charset=utf-8")
	w.Write(content)
}

func startServer(addr string) {
	mux := http.NewServeMux()
	mux.HandleFunc("/health", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		io.WriteString(w, "OK")
	})
	mux.HandleFunc("/ws", handleWS)
	mux.HandleFunc("/api/logs/file", handleLogFile)
	mux.HandleFunc("/api/logs", handleLogsAPI)
	mux.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		http.ServeFile(w, r, "static/index.html")
	})

	handler := basicAuth(mux)

	log.Printf("NetLogger listening on http://localhost%s", addr)
	if os.Getenv("NETLOGGER_PASSWORD") != "" {
		log.Println("HTTP Basic Auth enabled (NETLOGGER_PASSWORD is set)")
	}
	log.Fatal(http.ListenAndServe(addr, handler))
}
