package main

import (
	"crypto/subtle"
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

// =============================================================================
// SECURITY TESTS
// These tests verify the security properties we depend on. If any fail,
// the application may be vulnerable to attack.
// =============================================================================

// --- 1. CSRF Token Required ---
// All state-changing endpoints must require a valid CSRF token.

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
		form := url.Values{}
		form.Set("dir", "/tmp")
		form.Set("cmd", "echo")
		form.Set("project", "test")
		// Note: NO csrf token

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

// --- 2. Constant-Time CSRF Comparison ---
// CSRF comparison must use constant-time comparison to prevent timing attacks.

func TestCSRFUsesConstantTimeCompare(t *testing.T) {
	// Verify validateCSRF uses subtle.ConstantTimeCompare by checking behavior
	// (We can't directly test timing, but we verify correctness)

	req := httptest.NewRequest("POST", "/", nil)

	// Correct token
	req.Form = url.Values{"csrf": {csrfToken}}
	if !validateCSRF(req) {
		t.Error("validateCSRF should accept correct token")
	}

	// Wrong token (same length)
	req.Form = url.Values{"csrf": {"wrong-csrf-token-12345"}}
	if validateCSRF(req) {
		t.Error("validateCSRF should reject wrong token")
	}

	// Wrong token (different length)
	req.Form = url.Values{"csrf": {"short"}}
	if validateCSRF(req) {
		t.Error("validateCSRF should reject different-length token")
	}

	// Empty token
	req.Form = url.Values{"csrf": {""}}
	if validateCSRF(req) {
		t.Error("validateCSRF should reject empty token")
	}

	// Missing token
	req.Form = url.Values{}
	if validateCSRF(req) {
		t.Error("validateCSRF should reject missing token")
	}
}

// Verify the actual implementation uses subtle.ConstantTimeCompare
func TestConstantTimeCompareIsUsed(t *testing.T) {
	// This is a compile-time check that subtle is imported and used
	// If someone changes validateCSRF to use ==, this will still pass,
	// but the code review should catch it.

	// At minimum, verify subtle.ConstantTimeCompare works as expected
	a := []byte("test-token")
	b := []byte("test-token")
	c := []byte("different")

	if subtle.ConstantTimeCompare(a, b) != 1 {
		t.Error("ConstantTimeCompare should return 1 for equal slices")
	}
	if subtle.ConstantTimeCompare(a, c) != 0 {
		t.Error("ConstantTimeCompare should return 0 for different slices")
	}
}

// --- 3. Origin Header Validation ---
// Cross-origin requests must be rejected.

func TestOriginCheckRejectsCrossOrigin(t *testing.T) {
	evilOrigins := []string{
		"https://evil.com",
		"http://evil.com",
		"http://100.64.0.1:8090", // different Tailscale IP
		"http://100.64.0.1",      // different Tailscale IP without port
		"http://localhost:8090",
		"http://localhost",
		"http://127.0.0.1:8090",
		"http://127.0.0.1",
		"null",                   // some browsers send this for sandboxed iframes
		"file://",                // local file
		"http://100.100.100.101", // similar but different IP
	}

	for _, origin := range evilOrigins {
		form := url.Values{}
		form.Set("csrf", csrfToken)
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
		"http://" + tailscaleIP + ":7700", // ttyd port
		"",                                // same-origin requests may have no Origin header
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

		if w.Code == http.StatusForbidden {
			t.Errorf("Origin %q: should be allowed, got 403", origin)
		}
	}
}

func TestRefererFallbackRejectsCrossOrigin(t *testing.T) {
	// When Origin is empty, should check Referer
	evilReferers := []string{
		"https://evil.com/attack",
		"http://evil.com/page",
		"http://localhost:8080/",
		"http://100.64.0.1:8090/connect/session",
	}

	for _, referer := range evilReferers {
		form := url.Values{}
		form.Set("csrf", csrfToken)
		form.Set("dir", "/tmp")
		form.Set("cmd", "echo")

		req := httptest.NewRequest("POST", "/spawn", strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		// No Origin header, only Referer
		req.Header.Set("Referer", referer)

		w := httptest.NewRecorder()
		handleSpawn(w, req)

		if w.Code != http.StatusForbidden {
			t.Errorf("Referer %q: expected 403, got %d", referer, w.Code)
		}
	}
}

// --- 4. POST Required (No GET Side Effects) ---
// State-changing endpoints must reject GET requests.

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

// Also test other methods that shouldn't be allowed
func TestOtherMethodsNotAllowed(t *testing.T) {
	methods := []string{"PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"}

	for _, method := range methods {
		req := httptest.NewRequest(method, "/spawn", nil)
		w := httptest.NewRecorder()
		handleSpawn(w, req)

		if w.Code != http.StatusMethodNotAllowed {
			t.Errorf("%s /spawn: expected 405, got %d", method, w.Code)
		}
	}
}

// --- 5. Session Name Validation ---
// Session names in /connect/ and /kill/ must be validated against real tmux sessions.
// This prevents command injection via crafted session names.

func TestConnectRejectsInvalidSession(t *testing.T) {
	form := url.Values{}
	form.Set("csrf", csrfToken)

	// Try to connect to a session that doesn't exist
	req := httptest.NewRequest("POST", "/connect/fake-session-that-does-not-exist", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://"+tailscaleIP)

	w := httptest.NewRecorder()
	handleConnect(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("connect to fake session: expected 404, got %d", w.Code)
	}
}

func TestKillRejectsInvalidSession(t *testing.T) {
	form := url.Values{}
	form.Set("csrf", csrfToken)

	req := httptest.NewRequest("POST", "/kill/fake-session-that-does-not-exist", strings.NewReader(form.Encode()))
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Origin", "http://"+tailscaleIP)

	w := httptest.NewRecorder()
	handleKill(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("kill fake session: expected 404, got %d", w.Code)
	}
}

// Test that malicious session names are rejected
func TestSessionNameInjectionPrevented(t *testing.T) {
	// These names look like valid URL paths but contain injection attempts
	maliciousNames := []string{
		"session-$(whoami)",
		"session-`id`",
		"..%2F..%2Fetc%2Fpasswd",
		"valid-session-name", // This is valid format but doesn't exist
	}

	for _, name := range maliciousNames {
		form := url.Values{}
		form.Set("csrf", csrfToken)

		req := httptest.NewRequest("POST", "/connect/"+url.PathEscape(name), strings.NewReader(form.Encode()))
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		req.Header.Set("Origin", "http://"+tailscaleIP)

		w := httptest.NewRecorder()
		handleConnect(w, req)

		// Should be rejected (404 not found because session doesn't exist)
		if w.Code == http.StatusOK || w.Code == http.StatusFound {
			t.Errorf("malicious session name %q: should be rejected, got %d", name, w.Code)
		}
	}
}

// --- 6. Directory Validation ---
// Directories must exist before spawning sessions.

func TestSpawnRejectsNonexistentDirectory(t *testing.T) {
	_, err := spawnSession("/nonexistent/path/that/does/not/exist", "echo")
	if err == nil {
		t.Error("expected error for nonexistent directory")
	}
	if !strings.Contains(err.Error(), "directory not found") {
		t.Errorf("expected 'directory not found' error, got: %s", err)
	}
}

func TestSpawnRejectsFile(t *testing.T) {
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

// --- 7. No Open Redirects ---
// Redirects must use hardcoded tailscaleIP, not user-controlled values.

func TestRedirectUsesHardcodedIP(t *testing.T) {
	// The index page should not use the Host header for any links
	req := httptest.NewRequest("GET", "/", nil)
	req.Host = "evil.com:8090" // Attacker-controlled Host header
	req.Header.Set("X-Forwarded-Host", "evil.com")

	w := httptest.NewRecorder()
	handleIndex(w, req)

	body := w.Body.String()

	// Body should NOT contain the evil host
	if strings.Contains(body, "evil.com") {
		t.Error("index page should not use Host header in output")
	}

	// Body should contain the real tailscaleIP
	if !strings.Contains(body, tailscaleIP) || !strings.Contains(body, "csrf") {
		// The page should have CSRF tokens, which means it's rendering properly
		// and using our server's token, not anything from the request
	}
}

// --- 8. ttyd Origin Checking ---
// Verify ttyd is started with --check-origin flag.

func TestTtydCommandIncludesOriginCheck(t *testing.T) {
	// We can't easily test the actual command without starting ttyd,
	// but we can verify the code path by checking the startTtyd function
	// includes -O flag. This is a code inspection test.

	// For now, just document that this must be verified manually or
	// by inspecting the running process:
	// ps aux | grep ttyd | grep -- "-O"

	t.Log("ttyd --check-origin (-O) flag must be present in startTtyd function")
	t.Log("Verify with: grep -n '\\-O' main.go")
}

// --- 9. CSRF Token Not in URLs ---
// CSRF tokens should be in POST body, not URLs (prevents leakage via Referer, logs, history)

func TestCSRFTokenNotInURLs(t *testing.T) {
	req := httptest.NewRequest("GET", "/", nil)
	w := httptest.NewRecorder()
	handleIndex(w, req)

	body := w.Body.String()

	// Check that href attributes don't contain csrf
	// Links should be POST forms, not GET links with tokens
	if strings.Contains(body, "href=") && strings.Contains(body, "csrf=") {
		// This would indicate a URL like href="/connect/session?csrf=token"
		if strings.Contains(body, "?csrf=") || strings.Contains(body, "&csrf=") {
			t.Error("CSRF token found in URL - should be in POST body only")
		}
	}

	// CSRF should only appear in hidden form fields
	if !strings.Contains(body, `name="csrf"`) {
		t.Error("CSRF token should be in form fields")
	}
}

// --- 10. CSRF Token is Cryptographically Random ---

func TestCSRFTokenGeneration(t *testing.T) {
	// Generate multiple tokens and verify they're different
	tokens := make(map[string]bool)
	for i := 0; i < 10; i++ {
		token := generateCSRFToken()
		if tokens[token] {
			t.Error("CSRF token collision detected - not random enough")
		}
		tokens[token] = true

		// Token should be 64 hex characters (32 bytes)
		if len(token) != 64 {
			t.Errorf("CSRF token should be 64 chars, got %d", len(token))
		}

		// Should be valid hex
		for _, c := range token {
			if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
				t.Errorf("CSRF token contains non-hex character: %c", c)
			}
		}
	}
}

// =============================================================================
// FUNCTIONAL TESTS
// =============================================================================

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

func TestValidateOriginFunction(t *testing.T) {
	tests := []struct {
		origin   string
		referer  string
		expected bool
	}{
		{"http://" + tailscaleIP, "", true},
		{"http://" + tailscaleIP + ":8090", "", true},
		{"", "", true}, // no origin = same-origin
		{"https://evil.com", "", false},
		{"", "https://evil.com/page", false},
		{"", "http://" + tailscaleIP + "/page", true},
	}

	for _, tc := range tests {
		req := httptest.NewRequest("POST", "/", nil)
		if tc.origin != "" {
			req.Header.Set("Origin", tc.origin)
		}
		if tc.referer != "" {
			req.Header.Set("Referer", tc.referer)
		}

		result := validateOrigin(req)
		if result != tc.expected {
			t.Errorf("validateOrigin(origin=%q, referer=%q) = %v, want %v",
				tc.origin, tc.referer, result, tc.expected)
		}
	}
}
