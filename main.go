package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/hex"
	"fmt"
	"html/template"
	"log"
	mathrand "math/rand"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// Track running ttyd instances
type ttydInstance struct {
	port     int
	cmd      *exec.Cmd
	password string // random password for basic auth
}

// Config for spawn restrictions
type Config struct {
	AllowedCommands    []string `yaml:"allowed_commands"`
	AllowedDirectories []string `yaml:"allowed_directories"`
}

var (
	ttydInstances = make(map[string]*ttydInstance)
	portMutex     sync.Mutex
	nextPort      = 7700
	freePorts     []int // reclaimed ports to reuse
	tailscaleIP   string
	csrfToken     string  // generated at startup, required for POST requests
	config        *Config // nil = spawn disabled
)

var (
	adjectives = []string{"clever", "sleepy", "happy", "busy", "cozy", "gentle", "curious", "eager", "nimble", "quick"}
	nouns      = []string{"otter", "panda", "fox", "rabbit", "owl", "mouse", "seal", "frog", "duck", "wren"}
)

func generateCSRFToken() string {
	bytes := make([]byte, 32)
	rand.Read(bytes)
	return hex.EncodeToString(bytes)
}

func loadConfig() *Config {
	home, _ := os.UserHomeDir()
	configPath := filepath.Join(home, ".config", "agent-phone", "config.yaml")

	data, err := os.ReadFile(configPath)
	if err != nil {
		return nil // No config = spawn disabled
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		log.Printf("Warning: invalid config file: %v", err)
		return nil
	}

	// Expand ~ in directory paths
	for i, dir := range cfg.AllowedDirectories {
		if strings.HasPrefix(dir, "~/") {
			cfg.AllowedDirectories[i] = filepath.Join(home, dir[2:])
		} else if dir == "~" {
			cfg.AllowedDirectories[i] = home
		}
	}

	return &cfg
}

func isCommandAllowed(cmd string) bool {
	if config == nil {
		return false
	}
	for _, allowed := range config.AllowedCommands {
		if cmd == allowed {
			return true
		}
	}
	return false
}

func isDirectoryAllowed(dir string) bool {
	if config == nil {
		return false
	}
	// Resolve to absolute path
	absDir, err := filepath.Abs(dir)
	if err != nil {
		return false
	}
	// Check if under any allowed directory
	for _, allowed := range config.AllowedDirectories {
		absAllowed, err := filepath.Abs(allowed)
		if err != nil {
			continue
		}
		// Must be exactly the allowed dir or a subdirectory
		if absDir == absAllowed || strings.HasPrefix(absDir, absAllowed+"/") {
			return true
		}
	}
	return false
}

func validateCSRF(r *http.Request) bool {
	return subtle.ConstantTimeCompare([]byte(r.FormValue("csrf")), []byte(csrfToken)) == 1
}

func validateOrigin(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	if origin == "" {
		// Referer is sent on form submissions when Origin isn't
		referer := r.Header.Get("Referer")
		if referer != "" {
			origin = referer
		}
	}
	// Same-origin requests may have no Origin header
	if origin == "" {
		return true
	}
	// Must come from our own server
	allowed := "http://" + tailscaleIP
	return strings.HasPrefix(origin, allowed)
}

func main() {
	mathrand.Seed(time.Now().UnixNano())
	csrfToken = generateCSRFToken()
	config = loadConfig()

	if config != nil {
		log.Printf("Spawn enabled - allowed commands: %v", config.AllowedCommands)
		log.Printf("Spawn enabled - allowed directories: %v", config.AllowedDirectories)
	} else {
		log.Printf("Spawn disabled - no config at ~/.config/agent-phone/config.yaml")
	}

	http.HandleFunc("/", handleIndex)
	http.HandleFunc("/connect/", handleConnect)
	http.HandleFunc("/spawn", handleSpawn)
	http.HandleFunc("/spawn-project", handleSpawnProject)
	http.HandleFunc("/kill/", handleKill)

	// Get Tailscale IP - fail if unavailable (security: never bind to all interfaces)
	out, err := exec.Command("tailscale", "ip", "-4").Output()
	if err != nil {
		log.Fatal("Tailscale IP not available - refusing to start. Ensure Tailscale is running and logged in.")
	}
	tailscaleIP = strings.TrimSpace(string(out))
	if tailscaleIP == "" {
		log.Fatal("Tailscale returned empty IP - refusing to start.")
	}
	addr := tailscaleIP + ":8090"

	// Clean up orphaned ttyd processes every 30 seconds
	go cleanupOrphanedTtyd()

	url := fmt.Sprintf("http://%s", addr)
	fmt.Println()
	fmt.Println("===========================================")
	fmt.Printf("  agent-phone running at: %s\n", url)
	fmt.Println("===========================================")
	fmt.Println()
	log.Fatal(http.ListenAndServe(addr, nil))
}

// Clean up ttyd instances for sessions that no longer exist
func cleanupOrphanedTtyd() {
	for {
		time.Sleep(30 * time.Second)

		sessions, err := getTmuxSessions()
		if err != nil {
			continue
		}
		sessionSet := make(map[string]bool)
		for _, s := range sessions {
			sessionSet[s] = true
		}

		portMutex.Lock()
		for name, inst := range ttydInstances {
			if !sessionSet[name] {
				log.Printf("Cleaning up ttyd for ended session %q", name)
				inst.cmd.Process.Kill()
				inst.cmd.Wait()                          // reap zombie
				freePorts = append(freePorts, inst.port) // reclaim port
				delete(ttydInstances, name)
			}
		}
		portMutex.Unlock()
	}
}

// List tmux sessions
func getTmuxSessions() ([]string, error) {
	out, err := exec.Command("tmux", "list-sessions", "-F", "#{session_name}").Output()
	if err != nil {
		return nil, err
	}
	lines := strings.Split(strings.TrimSpace(string(out)), "\n")
	var sessions []string
	for _, line := range lines {
		if line != "" {
			sessions = append(sessions, line)
		}
	}
	return sessions, nil
}

// Start ttyd for a session, return port and password for basic auth
func startTtyd(session string) (int, string, error) {
	portMutex.Lock()
	defer portMutex.Unlock()

	// Already running?
	if inst, ok := ttydInstances[session]; ok {
		return inst.port, inst.password, nil
	}

	// Reuse a free port or allocate a new one
	var port int
	if len(freePorts) > 0 {
		port = freePorts[len(freePorts)-1]
		freePorts = freePorts[:len(freePorts)-1]
	} else {
		if nextPort > 65535 {
			return 0, "", fmt.Errorf("no ports available")
		}
		port = nextPort
		nextPort++
	}

	// Generate random password for this ttyd instance
	// This protects against cross-origin WebSocket attacks - browser won't send credentials cross-origin
	pwdBytes := make([]byte, 16)
	rand.Read(pwdBytes)
	password := hex.EncodeToString(pwdBytes)
	credential := "t:" + password // username is just "t", password is random

	// Bind ttyd to Tailscale IP only, with larger font for mobile
	// -c: require basic auth (protects against cross-origin attacks since browser won't send credentials)
	// -O: also check Origin header (defense in depth for future browser behavior changes)
	cmd := exec.Command("ttyd", "-i", tailscaleIP, "-p", fmt.Sprintf("%d", port), "-W", "-O", "-c", credential, "-t", "fontSize=32", "tmux", "attach", "-t", session)
	if err := cmd.Start(); err != nil {
		return 0, "", err
	}

	ttydInstances[session] = &ttydInstance{port: port, cmd: cmd, password: password}

	// Wait in background to avoid zombie processes and clean up on exit
	go func() {
		cmd.Wait()
		portMutex.Lock()
		if inst, ok := ttydInstances[session]; ok && inst.cmd == cmd {
			log.Printf("ttyd for session %q exited, cleaning up", session)
			freePorts = append(freePorts, inst.port)
			delete(ttydInstances, session)
		}
		portMutex.Unlock()
	}()
	log.Printf("Started ttyd for session %q on port %d", session, port)

	// Wait for ttyd to be ready (up to 2 seconds)
	addr := fmt.Sprintf("%s:%d", tailscaleIP, port)
	ready := false
	for i := 0; i < 20; i++ {
		conn, err := net.DialTimeout("tcp", addr, 100*time.Millisecond)
		if err == nil {
			conn.Close()
			ready = true
			break
		}
		time.Sleep(100 * time.Millisecond)
	}

	if !ready {
		// ttyd probably failed to start (bad flag, missing binary, etc.)
		portMutex.Lock()
		delete(ttydInstances, session)
		freePorts = append(freePorts, port)
		portMutex.Unlock()
		return 0, "", fmt.Errorf("ttyd failed to start on port %d", port)
	}

	return port, password, nil
}

// Group sessions by project directory (from AGENT_TMUX_DIR env var)
func groupSessionsByProject(sessions []string) map[string][]string {
	groups := make(map[string][]string)
	for _, s := range sessions {
		project := "other"
		// Try to get project from tmux environment
		out, err := exec.Command("tmux", "show-environment", "-t", s, "AGENT_TMUX_DIR").Output()
		if err == nil {
			line := strings.TrimSpace(string(out))
			if strings.HasPrefix(line, "AGENT_TMUX_DIR=") {
				dir := strings.TrimPrefix(line, "AGENT_TMUX_DIR=")
				// Make path relative to home directory
				home, _ := os.UserHomeDir()
				if dir == home {
					project = "~"
				} else if strings.HasPrefix(dir, home+"/") {
					project = strings.TrimPrefix(dir, home+"/")
				} else {
					project = dir
				}
			}
		} else {
			// Fallback: parse from session name (cmd-PROJECT-adj-noun)
			parts := strings.Split(s, "-")
			if len(parts) >= 4 {
				project = strings.Join(parts[1:len(parts)-2], "-")
			} else if len(parts) >= 2 {
				project = parts[1]
			}
		}
		groups[project] = append(groups[project], s)
	}
	return groups
}

func handleIndex(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	sessions, err := getTmuxSessions()
	if err != nil {
		sessions = []string{}
	}

	groups := groupSessionsByProject(sessions)

	tmpl := template.Must(template.New("index").Parse(`<!DOCTYPE html>
<html>
<head>
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Claude Sessions</title>
    <style>
        body {
            font-family: -apple-system, BlinkMacSystemFont, sans-serif;
            background: #1a1a2e;
            color: #eee;
            margin: 0;
            padding: 16px;
        }
        h1 {
            font-size: 24px;
            margin-bottom: 20px;
        }
        h2 {
            font-size: 18px;
            color: #888;
            margin: 24px 0 12px 0;
            border-bottom: 1px solid #333;
            padding-bottom: 8px;
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .session {
            display: block;
            background: #16213e;
            border: 1px solid #0f3460;
            border-radius: 12px;
            padding: 20px;
            margin-bottom: 12px;
            text-decoration: none;
            color: #eee;
            font-size: 18px;
        }
        .session:active {
            background: #0f3460;
        }
        .session-row {
            display: flex;
            align-items: center;
            margin-bottom: 12px;
        }
        .session-row .session {
            flex: 1;
            margin-bottom: 0;
        }
        .kill-btn {
            background: #4a1a1a;
            border: none;
            border-radius: 8px;
            padding: 12px 16px;
            margin-left: 8px;
            color: #ff6b6b;
            font-size: 16px;
            cursor: pointer;
        }
        .kill-btn:active {
            background: #6a2a2a;
        }
        .empty {
            color: #666;
            font-style: italic;
        }
        .new-session {
            background: #16213e;
            border: 1px solid #0f3460;
            border-radius: 12px;
            padding: 16px;
            margin-bottom: 24px;
        }
        .new-session input {
            background: #1a1a2e;
            border: 1px solid #0f3460;
            border-radius: 8px;
            padding: 12px;
            color: #eee;
            font-size: 16px;
            width: 100%;
            box-sizing: border-box;
            margin-bottom: 8px;
        }
        .new-session button, .add-btn {
            background: #0f3460;
            border: none;
            border-radius: 8px;
            padding: 12px 20px;
            color: #eee;
            font-size: 16px;
            cursor: pointer;
        }
        .new-session button:active, .add-btn:active {
            background: #1a5490;
        }
        .add-btn {
            padding: 4px 12px;
            font-size: 14px;
        }
    </style>
    
</head>
<body>
    <h1>Claude Sessions</h1>
    
    {{if .SpawnEnabled}}
    <form class="new-session" action="/spawn" method="POST">
        <input type="hidden" name="csrf" value="{{.CSRFToken}}">
        <input name="dir" placeholder="/path/to/project" required>
        <input name="cmd" placeholder="claude" value="claude">
        <button type="submit">+ New Session</button>
    </form>
    {{end}}

    {{if .Groups}}
        {{range $project, $sessions := .Groups}}
        <h2>
            <span>{{$project}}</span>
            {{if $.SpawnEnabled}}
            <form action="/spawn-project" method="POST" style="display:inline;margin:0;">
                <input type="hidden" name="csrf" value="{{$.CSRFToken}}">
                <input type="hidden" name="project" value="{{$project}}">
                <input type="hidden" name="cmd" value="claude">
                <button type="submit" class="add-btn">+</button>
            </form>
            {{end}}
        </h2>
        {{range $sessions}}
        <div class="session-row">
            <form action="/connect/{{.}}" method="POST" style="display:contents;">
                <input type="hidden" name="csrf" value="{{$.CSRFToken}}">
                <button type="submit" class="session">{{.}}</button>
            </form>
            <form action="/kill/{{.}}" method="POST" style="margin:0;">
                <input type="hidden" name="csrf" value="{{$.CSRFToken}}">
                <button type="submit" class="kill-btn">✕</button>
            </form>
        </div>
        {{end}}
        {{end}}
    {{else}}
        <p class="empty">No tmux sessions running</p>
    {{end}}
</body>
</html>`))

	tmpl.Execute(w, map[string]interface{}{
		"Groups":       groups,
		"CSRFToken":    csrfToken,
		"SpawnEnabled": config != nil,
	})
}

func handleConnect(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")

	if r.Method != "POST" {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if !validateCSRF(r) || !validateOrigin(r) {
		http.Error(w, "invalid request", http.StatusForbidden)
		return
	}

	session := strings.TrimPrefix(r.URL.Path, "/connect/")
	if session == "" {
		http.Error(w, "no session specified", http.StatusBadRequest)
		return
	}

	// Validate session exists (also prevents injection - only real session names accepted)
	sessions, err := getTmuxSessions()
	if err != nil {
		http.Error(w, "failed to list sessions", http.StatusInternalServerError)
		return
	}
	valid := false
	for _, s := range sessions {
		if s == session {
			valid = true
			break
		}
	}
	if !valid {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	port, password, err := startTtyd(session)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Redirect to ttyd with credentials in URL (browser will prompt for auth and cache it)
	// Format: http://user:pass@host:port/
	http.Redirect(w, r, fmt.Sprintf("http://t:%s@%s:%d/?t=%d", password, tailscaleIP, port, time.Now().UnixNano()), http.StatusFound)
}

// Get directory for a project by checking existing sessions
func getProjectDir(project string) string {
	sessions, err := getTmuxSessions()
	if err != nil {
		return ""
	}
	for _, s := range sessions {
		parts := strings.Split(s, "-")
		if len(parts) >= 4 {
			sessionProject := strings.Join(parts[1:len(parts)-2], "-")
			if sessionProject == project {
				// Found a session for this project, get its directory
				out, err := exec.Command("tmux", "show-environment", "-t", s, "AGENT_TMUX_DIR").Output()
				if err == nil {
					line := strings.TrimSpace(string(out))
					if strings.HasPrefix(line, "AGENT_TMUX_DIR=") {
						return strings.TrimPrefix(line, "AGENT_TMUX_DIR=")
					}
				}
			}
		}
	}
	return ""
}

// Generate a unique session name
func generateSessionName(cmd, project string) string {
	sessions, _ := getTmuxSessions()
	sessionSet := make(map[string]bool)
	for _, s := range sessions {
		sessionSet[s] = true
	}

	for i := 0; i < 10; i++ {
		adj := adjectives[mathrand.Intn(len(adjectives))]
		noun := nouns[mathrand.Intn(len(nouns))]
		name := fmt.Sprintf("%s-%s-%s-%s", cmd, project, adj, noun)
		if !sessionSet[name] {
			return name
		}
	}
	// Fallback with timestamp
	return fmt.Sprintf("%s-%s-%d", cmd, project, time.Now().Unix())
}

// Spawn a new session in a directory
func spawnSession(dir, cmd string) (string, error) {
	// Check directory exists
	info, err := os.Stat(dir)
	if err != nil {
		return "", fmt.Errorf("directory not found: %s", dir)
	}
	if !info.IsDir() {
		return "", fmt.Errorf("not a directory: %s", dir)
	}

	project := filepath.Base(dir)
	session := generateSessionName(cmd, project)

	// Create detached tmux session
	tmux := exec.Command("tmux", "new-session", "-d", "-s", session, "-c", dir, cmd)
	if err := tmux.Run(); err != nil {
		return "", err
	}

	// Store environment variables
	exec.Command("tmux", "set-environment", "-t", session, "AGENT_TMUX_DIR", dir).Run()
	exec.Command("tmux", "set-environment", "-t", session, "AGENT_TMUX_CMD", cmd).Run()

	return session, nil
}

func handleSpawn(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != "POST" {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if !validateCSRF(r) || !validateOrigin(r) {
		http.Error(w, "invalid request", http.StatusForbidden)
		return
	}

	// Check if spawn is enabled
	if config == nil {
		http.Error(w, "spawn disabled - no config file", http.StatusForbidden)
		return
	}

	dir := r.FormValue("dir")
	cmd := r.FormValue("cmd")
	if cmd == "" {
		cmd = "claude"
	}
	if dir == "" {
		http.Error(w, "dir required", http.StatusBadRequest)
		return
	}

	// Expand ~ to home directory
	if strings.HasPrefix(dir, "~") {
		home, _ := os.UserHomeDir()
		dir = home + strings.TrimPrefix(dir, "~")
	}

	// Validate against allowlists
	if !isCommandAllowed(cmd) {
		http.Error(w, fmt.Sprintf("command %q not allowed", cmd), http.StatusForbidden)
		return
	}
	if !isDirectoryAllowed(dir) {
		http.Error(w, fmt.Sprintf("directory %q not allowed", dir), http.StatusForbidden)
		return
	}

	session, err := spawnSession(dir, cmd)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Start ttyd and redirect directly to it
	port, password, err := startTtyd(session)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("http://t:%s@%s:%d/?t=%d", password, tailscaleIP, port, time.Now().UnixNano()), http.StatusFound)
}

func handleKill(w http.ResponseWriter, r *http.Request) {
	if r.Method != "POST" {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if !validateCSRF(r) || !validateOrigin(r) {
		http.Error(w, "invalid request", http.StatusForbidden)
		return
	}

	session := strings.TrimPrefix(r.URL.Path, "/kill/")
	if session == "" {
		http.Error(w, "session required", http.StatusBadRequest)
		return
	}

	// Validate session exists
	sessions, err := getTmuxSessions()
	if err != nil {
		http.Error(w, "failed to list sessions", http.StatusInternalServerError)
		return
	}
	valid := false
	for _, s := range sessions {
		if s == session {
			valid = true
			break
		}
	}
	if !valid {
		http.Error(w, "session not found", http.StatusNotFound)
		return
	}

	// Kill the tmux session
	exec.Command("tmux", "kill-session", "-t", session).Run()

	http.Redirect(w, r, "/", http.StatusFound)
}

func handleSpawnProject(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Cache-Control", "no-store")
	if r.Method != "POST" {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}
	if !validateCSRF(r) || !validateOrigin(r) {
		http.Error(w, "invalid request", http.StatusForbidden)
		return
	}

	// Check if spawn is enabled
	if config == nil {
		http.Error(w, "spawn disabled - no config file", http.StatusForbidden)
		return
	}

	project := r.FormValue("project")
	if project == "" {
		http.Error(w, "project required", http.StatusBadRequest)
		return
	}

	// First try to get directory from existing session for this project
	dir := getProjectDir(project)
	if dir == "" {
		// No existing session - resolve the path but validate it
		home, _ := os.UserHomeDir()
		if project == "~" {
			dir = home
		} else if strings.HasPrefix(project, "/") {
			dir = project
		} else {
			dir = filepath.Join(home, project)
		}
	}

	// Resolve to absolute and clean path (handles ../)
	absDir, err := filepath.Abs(dir)
	if err != nil {
		http.Error(w, "invalid directory path", http.StatusBadRequest)
		return
	}
	dir = absDir

	cmd := r.FormValue("cmd")
	if cmd == "" {
		cmd = "claude"
	}

	// Validate against allowlists
	if !isCommandAllowed(cmd) {
		http.Error(w, fmt.Sprintf("command %q not allowed", cmd), http.StatusForbidden)
		return
	}
	if !isDirectoryAllowed(dir) {
		http.Error(w, fmt.Sprintf("directory %q not allowed", dir), http.StatusForbidden)
		return
	}

	session, err := spawnSession(dir, cmd)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	// Start ttyd and redirect directly to it
	port, password, err := startTtyd(session)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	http.Redirect(w, r, fmt.Sprintf("http://t:%s@%s:%d/?t=%d", password, tailscaleIP, port, time.Now().UnixNano()), http.StatusFound)
}
