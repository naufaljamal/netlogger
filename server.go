package main

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/creack/pty"
	"github.com/gorilla/websocket"
)

var upgrader = websocket.Upgrader{
	CheckOrigin: func(r *http.Request) bool { return true },
}

type wsMsg struct {
	Type     string `json:"type"`
	Device   string `json:"device,omitempty"`
	Username string `json:"username,omitempty"`
	Password string `json:"password,omitempty"`
	Data     string `json:"data,omitempty"`
	Message  string `json:"message,omitempty"`
	Cols     uint16 `json:"cols,omitempty"`
	Rows     uint16 `json:"rows,omitempty"`
}

func startServer(addr string) {
	http.HandleFunc("/ws", handleWS)
	http.HandleFunc("/api/logs", handleLogsAPI)
	http.HandleFunc("/api/logs/file", handleLogFile)
	// Serve everything in static/ (images, fonts, etc.) under /static/
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	http.HandleFunc("/", serveIndex)
	log.Printf("NetLogger: http://localhost%s\n", addr)
	log.Fatal(http.ListenAndServe(addr, nil))
}

func serveIndex(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/" {
		http.NotFound(w, r)
		return
	}
	http.ServeFile(w, r, "static/index.html")
}

// cmdTracker accumulates raw terminal input bytes and fires onWriteMem when
// a write mem variant is detected. Not goroutine-safe; call from one goroutine.
type cmdTracker struct {
	buf   strings.Builder
	inEsc bool
}

func (t *cmdTracker) process(data []byte, onWriteMem func()) {
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
		log.Printf("WebSocket upgrade error: %v", err)
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
		if sess != nil {
			sess.commitLog(fmt.Sprintf("netcli-web: [%s] session ended", sess.device))
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
			sess = newSession(
				msg.Device, msg.Username,
				fmt.Sprintf("netcli-web: [%s] session by %s", msg.Device, msg.Username),
			)
			cmd = exec.Command("ssh",
				"-o", "StrictHostKeyChecking=no",
				"-o", "UserKnownHostsFile=/dev/null",
				fmt.Sprintf("%s@%s", msg.Username, msg.Device),
			)
			ptmx, err = pty.Start(cmd)
			if err != nil {
				send(wsMsg{Type: "error", Message: err.Error()})
				sess, cmd = nil, nil
				continue
			}

			send(wsMsg{Type: "connected"})

			// PTY output → WebSocket
			go func() {
				buf := make([]byte, 4096)
				for {
					n, err := ptmx.Read(buf)
					if n > 0 {
						sess.rawBufMu.Lock()
						sess.rawBuf.Write(buf[:n])
						sess.rawBufMu.Unlock()
						send(wsMsg{
							Type: "output",
							Data: base64.StdEncoding.EncodeToString(buf[:n]),
						})
					}
					if err != nil {
						break
					}
				}
				send(wsMsg{Type: "disconnected"})
			}()

			// Periodic auto-commit
			tickerDone = make(chan struct{})
			go func(s *Session, done <-chan struct{}) {
				ticker := time.NewTicker(5 * time.Minute)
				defer ticker.Stop()
				for {
					select {
					case <-ticker.C:
						s.commitLog(fmt.Sprintf("netcli-web: [%s] auto-commit (5-min interval)", s.device))
					case <-done:
						return
					}
				}
			}(sess, tickerDone)

		case "input":
			if ptmx == nil {
				continue
			}
			data, err := base64.StdEncoding.DecodeString(msg.Data)
			if err != nil {
				continue
			}
			if sess != nil {
				tracker.process(data, func() {
					sess.commitLog(fmt.Sprintf("netcli-web: [%s] auto-commit (write mem)", sess.device))
				})
			}
			ptmx.Write(data)

		case "resize":
			if ptmx != nil && msg.Cols > 0 && msg.Rows > 0 {
				pty.Setsize(ptmx, &pty.Winsize{Rows: msg.Rows, Cols: msg.Cols})
			}

		case "exit":
			if sess != nil {
				sess.commitLog(fmt.Sprintf("netcli-web: [%s] session by %s", sess.device, sess.username))
				send(wsMsg{Type: "committed", Message: "Session committed to GitLab"})
			}
			return
		}
	}
}

// handleLogsAPI returns log entries across a date range.
// GET /api/logs?from=2026-04-20&to=2026-04-24  →  [{device, file, path, date}, ...]
// GET /api/logs                                 →  ["2026-04-24", ...]  (available dates)
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
		json.NewEncoder(w).Encode(dates)
		return
	}

	// Normalise: if only one bound is given, treat it as a single-day query
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
