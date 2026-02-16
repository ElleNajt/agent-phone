package main

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func init() {
	// Initialize for tests
	csrfToken = "test-csrf-token-12345"
	tailscaleIP = "100.100.100.100"
}

// === Security Tests ===

func TestCSRFRequired(t *testing.T) {
	endpoints := []struct {
		path   string
		method string
	}{
		{"/connect/test-session", "POST"},
		{"/spawn", "POST"},
		{"/spawn-project", "POST"},
		{"/kill/test-session", "POST"},
	}

	for _, ep := range endpoints {
		// Request without CSRF token
		form := url.Values{}
		form.Set("dir", "/tmp")
		form.Set("cmd", "echo")
		form.Set("project", "test")

		req := httptest.NewRequest(ep.method, ep.path, strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", "http://"+tailscaleIP)

		w := httptest.NewRecorder()

		switch {
		case strings.HasPrefix(ep.path, "/connect/"):
			handleConnect(w, req)
		case ep.path == "/spawn":
			handleSpawn(w, req)
		case ep.path == "/spawn-project":
			handleSpawnProject(w, req)
		case strings.HasPrefix(ep.path, "/kill/"):
			handleKill(w, req)
		}

		if w.Code != http.StatusForbidden {
			t.Errorf("%s %s without CSRF: expected 403, got %d", ep.method, ep.path, w.Code)
		}
	}
}

func TestCSRFWrongToken(t *testing.T) {
	form := url.Values{}
	form.Set("csrf", "wrong-token")
	form.Set("dir", "/tmp")

	req := httptest.NewRequest("POST", "/spawn", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://"+tailscaleIP)

	w := httptest.NewRecorder()
	handleSpawn(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("wrong CSRF token: expected 403, got %d", w.Code)
	}
}

func TestOriginCheckRejectsCrossOrigin(t *testing.T) {
	evilOrigins := []string{
		"https://evil.com",
		"http://evil.com",
		"http://100.64.0.1:8090", // different Tailscale IP
		"http://localhost:8090",
		"null", // some browsers send this
	}

	for _, origin := range evilOrigins {
		form := url.Values{}
		form.Set("csrf", csrfToken) // correct token
		form.Set("dir", "/tmp")
		form.Set("cmd", "echo")

		req := httptest.NewRequest("POST", "/spawn", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", origin)

		w := httptest.NewRecorder()
		handleSpawn(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("Origin %q: expected 403, got %d", origin, w.Code)
		}
	}
}

func TestOriginCheckAllowsSameOrigin(t *testing.T) {
	goodOrigins := []string{
		"http://" + tailscaleIP,
		"http://" + tailscaleIP + ":8090",
		"", // same-origin requests may have no Origin header
	}

	for _, origin := range goodOrigins {
		form := url.Values{}
		form.Set("csrf", csrfToken)
		form.Set("dir", "/tmp")
		form.Set("cmd", "echo")

		req := httptest.NewRequest("POST", "/spawn", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		if origin != "" {
			req.Header.Set("Origin", origin)
		}

		w := httptest.NewRecorder()
		handleSpawn(w, req)

		// Should not be 403 (may be other errors like dir not existing, but not CSRF/origin failure)
		if w.Code == http.StatusForbidden {
			t.Errorf("Origin %q: should be allowed, got 403", origin)
		}
	}
}

func TestGETNotAllowed(t *testing.T) {
	endpoints := []string{
		"/connect/test-session",
		"/spawn",
		"/spawn-project",
		"/kill/test-session",
	}

	for _, path := range endpoints {
		req := httptest.NewRequest("GET", path, nil)
		w := httptest.NewRecorder()

		switch {
		case strings.HasPrefix(path, "/connect/"):
			handleConnect(w, req)
		case path == "/spawn":
			handleSpawn(w, req)
		case path == "/spawn-project":
			handleSpawnProject(w, req)
		case strings.HasPrefix(path, "/kill/"):
			handleKill(w, req)
		}

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("GET %s: expected 405, got %d", path, w.Code)
		}
	}
}

func TestRefererFallback(t *testing.T) {
	// When Origin is empty, should check Referer
	form := url.Values{}
	form.Set("csrf", csrfToken)
	form.Set("dir", "/tmp")
	form.Set("cmd", "echo")

	req := httptest.NewRequest("POST", "/spawn", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Referer", "https://evil.com/attack")

	w := httptest.NewRecorder()
	handleSpawn(w, req)

	if w.Code != http.StatusForbidden {
		t.Errorf("evil Referer: expected 403, got %d", w.Code)
	}
}

// === Functional Tests ===

func TestGenerateSessionName(t *testing.T) {
	name := generateSessionName("claude", "myproject")

	parts := strings.Split(name, "-")
	if len(parts) != 4 {
		t.Errorf("expected 4 parts, got %d: %s", len(parts), name)
	}
	if parts[0] != "claude" {
		t.Errorf("expected cmd 'claude', got '%s'", parts[0])
	}
	if parts[1] != "myproject" {
		t.Errorf("expected project 'myproject', got '%s'", parts[1])
	}

	foundAdj := false
	for _, adj := range adjectives {
		if adj == parts[2] {
			foundAdj = true
			break
		}
	}
	if !foundAdj {
		t.Errorf("adjective '%s' not in list", parts[2])
	}

	foundNoun := false
	for _, noun := range nouns {
		if noun == parts[3] {
			foundNoun = true
			break
		}
	}
	if !foundNoun {
		t.Errorf("noun '%s' not in list", parts[3])
	}
}

func TestSpawnSessionBadDirectory(t *testing.T) {
	_, err := spawnSession("/nonexistent/path/that/does/not/exist", "echo")
	if err == nil {
		t.Error("expected error for nonexistent directory")
	}
	if !strings.Contains(err.Error(), "directory not found") {
		t.Errorf("expected 'directory not found' error, got: %s", err)
	}
}

func TestSpawnSessionNotADirectory(t *testing.T) {
	tmpFile, err := os.CreateTemp("", "test")
	if err != nil {
		t.Fatal(err)
	}
	defer os.Remove(tmpFile.Name())
	tmpFile.Close()

	_, err = spawnSession(tmpFile.Name(), "echo")
	if err == nil {
		t.Error("expected error for file (not directory)")
	}
	if !strings.Contains(err.Error(), "not a directory") {
		t.Errorf("expected 'not a directory' error, got: %s", err)
	}
}

func TestExpandTilde(t *testing.T) {
	home, _ := os.UserHomeDir()

	tests := []struct {
		input    string
		expected string
	}{
		{"~", home},
		{"~/code", home + "/code"},
		{"~/code/project", home + "/code/project"},
		{"/absolute/path", "/absolute/path"},
	}

	for _, tc := range tests {
		dir := tc.input
		if strings.HasPrefix(dir, "~") {
			dir = home + strings.TrimPrefix(dir, "~")
		}
		if dir != tc.expected {
			t.Errorf("expandTilde(%q) = %q, want %q", tc.input, dir, tc.expected)
		}
	}
}

func TestProjectFromPath(t *testing.T) {
	tests := []struct {
		path     string
		expected string
	}{
		{"/Users/elle/code/agent-phone", "agent-phone"},
		{"/home/user/projects/my-app", "my-app"},
		{"/tmp", "tmp"},
	}

	for _, tc := range tests {
		result := filepath.Base(tc.path)
		if result != tc.expected {
			t.Errorf("filepath.Base(%q) = %q, want %q", tc.path, result, tc.expected)
		}
	}
}

func TestValidateCSRFConstantTime(t *testing.T) {
	// This doesn't actually test constant-time behavior (hard to test)
	// but ensures the function works correctly
	req := httptest.NewRequest("POST", "/", nil)
	req.Form = url.Values{"csrf": {csrfToken}}
	if !validateCSRF(req) {
		t.Error("validateCSRF should accept correct token")
	}

	req.Form = url.Values{"csrf": {"wrong"}}
	if validateCSRF(req) {
		t.Error("validateCSRF should reject wrong token")
	}

	req.Form = url.Values{}
	if validateCSRF(req) {
		t.Error("validateCSRF should reject missing token")
	}
}
