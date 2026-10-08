package stagingdiag

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestStage74DiagnosticAccess(t *testing.T) {
	now := time.Now()
	key := strings.Repeat("a", 64)
	reads := 0
	read := func() (any, error) { reads++; return map[string]any{"model": "gpt-5.6-luna"}, nil }
	handler := Handler(key, now.Add(time.Minute), read, func() time.Time { return now })
	for _, tc := range []struct {
		name, method, path, peer, auth, origin string
		code                                   int
	}{
		{"authorized", "GET", Path, "127.0.0.1:1000", "Bearer " + key, "", 200},
		{"missing key", "GET", Path, "127.0.0.1:1000", "", "", 401},
		{"wrong key", "GET", Path, "127.0.0.1:1000", "Bearer " + strings.Repeat("b", 64), "", 401},
		{"external even with key", "GET", Path, "172.18.0.2:1000", "Bearer " + key, "", 403},
		{"browser origin", "GET", Path, "127.0.0.1:1000", "Bearer " + key, "https://example.invalid", 403},
		{"mutation", "POST", Path, "127.0.0.1:1000", "Bearer " + key, "", 404},
		{"query target", "GET", Path + "?model=other", "127.0.0.1:1000", "Bearer " + key, "", 404},
		{"other path", "GET", "/api/option/", "127.0.0.1:1000", "Bearer " + key, "", 404},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)
			req.RemoteAddr = tc.peer
			req.Header.Set("Authorization", tc.auth)
			req.Header.Set("Origin", tc.origin)
			req.Header.Set("X-Forwarded-For", "127.0.0.1")
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, req)
			if got := response.Code; got != tc.code {
				t.Errorf("unexpected diagnostic result: got %v, want %v", got, tc.code)
			}
			if strings.Contains(response.Body.String(), key) {
				t.Error("diagnostic leaked authorization")
			}
			if got := response.Header().Get("Cache-Control"); got != "no-store" {
				t.Errorf("unexpected diagnostic result: got %v, want %v", got, "no-store")
			}
		})
	}
	if got := reads; got != 1 {
		t.Errorf("unexpected diagnostic result: got %v, want %v", got, 1)
	}
	now = now.Add(2 * time.Minute)
	req := httptest.NewRequest("GET", Path, nil)
	req.RemoteAddr = "127.0.0.1:1000"
	req.Header.Set("Authorization", "Bearer "+key)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, req)
	if got := response.Code; got != http.StatusGone {
		t.Errorf("unexpected diagnostic result: got %v, want %v", got, http.StatusGone)
	}
	if got := reads; got != 1 {
		t.Errorf("unexpected diagnostic result: got %v, want %v", got, 1)
	}
}

func TestStage74AuthorizationFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "operator.json")
	// A missing grant never starts a listener in either build variant.
	if err := Start(func() (any, error) { t.Fatal("startup must not read without authorization"); return nil, nil }); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(`{"purpose":"production","key":"short","expires":1}`), 0600); err != nil {
		t.Fatal(err)
	}
	_, err := loadGrant(path)
	if err == nil {
		t.Fatal("expected fail-closed error")
	}
	if err := os.Chmod(path, 0644); err != nil {
		t.Fatal(err)
	}
	_, err = loadGrant(path)
	if err == nil {
		t.Fatal("expected fail-closed error")
	}
}

func TestStage74StartupBuildGateAndGrant(t *testing.T) {
	if os.Geteuid() != 0 {
		t.Skip("staging authorization owner test requires isolated Linux root")
	}
	path := filepath.Join(t.TempDir(), "operator.json")
	original := grantPath
	if err := os.Chmod(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	grantPath = path
	t.Cleanup(func() { grantPath = original })
	key := strings.Repeat("c", 64)
	for _, tc := range []struct {
		purpose, key string
		expires      int64
		valid        bool
	}{
		{"local-staging", key, time.Now().Add(time.Minute).Unix(), true},
		{"production", key, time.Now().Add(time.Minute).Unix(), false},
		{"local-staging", "short", time.Now().Add(time.Minute).Unix(), false},
		{"local-staging", key, time.Now().Add(-time.Minute).Unix(), false},
		{"local-staging", key, time.Now().Add(time.Hour).Unix(), false},
	} {
		body := fmt.Sprintf(`{"purpose":%q,"key":%q,"expires":%d}`, tc.purpose, tc.key, tc.expires)
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		_, err := loadGrant(path)
		if (err == nil) != tc.valid {
			t.Fatal("authorization lifetime/purpose/key gate mismatch")
		}
	}
	body := fmt.Sprintf(`{"purpose":"local-staging","key":%q,"expires":%d}`, key, time.Now().Add(time.Minute).Unix())
	if err := os.WriteFile(path, []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
	if Enabled {
		if err := os.Chmod(filepath.Dir(path), 0755); err != nil {
			t.Fatal(err)
		}
		if err := Start(func() (any, error) { t.Fatal("unsafe directory invoked getter"); return nil, nil }); err == nil {
			t.Fatal("unsafe authorization directory accepted")
		}
		if err := os.Chmod(filepath.Dir(path), 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chown(path, 65534, 65534); err != nil {
			t.Fatal(err)
		}
		if err := Start(func() (any, error) { t.Fatal("wrong owner invoked getter"); return nil, nil }); err == nil {
			t.Fatal("unauthorized file owner accepted")
		}
		if err := os.Chown(path, 0, 0); err != nil {
			t.Fatal(err)
		}
	}
	if err := Start(func() (any, error) { return map[string]any{"diagnostic": "safe"}, nil }); err != nil {
		t.Fatal(err)
	}
	if !Enabled {
		conn, err := net.DialTimeout("tcp4", "127.0.0.1:19740", time.Second)
		if err == nil {
			_ = conn.Close()
			t.Fatal("ordinary build started diagnostic listener")
		}
		return
	}
	client := &http.Client{Timeout: time.Second}
	req, err := http.NewRequest("GET", "http://127.0.0.1:19740"+Path, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer "+key)
	resp, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatal("authorized tagged startup read failed")
	}
}
