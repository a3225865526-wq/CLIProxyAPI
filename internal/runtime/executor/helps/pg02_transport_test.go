package helps

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	coreexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

type pg02DenyGuard struct{}

// Executed only in an isolated Linux candidate's dedicated persistent mount.
func TestPG02PersistentPrivateMount(t *testing.T) {
	dir := os.Getenv("PG02_PRIVATE_MOUNT")
	if dir == "" {
		t.Skip("private-volume acceptance only")
	}
	t.Setenv("CLEARAPI_PG02_TRANSPORT_DIR", dir)
	before, err := filepath.Glob(filepath.Join(dir, "pg02-*.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	headers := make(http.Header)
	headers.Set("X-ClearAPI-PG02-Request", "volume-request")
	headers.Set("X-ClearAPI-PG02-Attempt", "volume-attempt")
	ctx, finish := PG02TransportContext(context.Background(), headers, "gpt-5.6-luna", "synthetic-volume-account", 1)
	client := NewUsageReporter(ctx, "codex", "gpt-5.6-luna", nil).TrackHTTPClient(&http.Client{Transport: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 400, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("synthetic rejection")), Request: req}, nil
	})})
	request, err := http.NewRequestWithContext(ctx, "POST", "https://synthetic.invalid/responses", nil)
	if err != nil {
		t.Fatal(err)
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	if err = response.Body.Close(); err != nil {
		t.Fatal(err)
	}
	finish()
	after, err := filepath.Glob(filepath.Join(dir, "pg02-*.jsonl"))
	if err != nil {
		t.Fatal(err)
	}
	if len(after) != len(before)+1 {
		t.Fatal("persistent receipt missing or replaced")
	}
	known := make(map[string]bool)
	for _, path := range before {
		known[path] = true
	}
	for _, path := range after {
		if known[path] {
			continue
		}
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm() != 0600 {
			t.Fatal("private file mode")
		}
		data, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		lines := strings.Split(strings.TrimSpace(string(data)), "\n")
		if len(lines) != 3 {
			t.Fatal("receipt lifecycle")
		}
		var final map[string]any
		if err = json.Unmarshal([]byte(lines[2]), &final); err != nil {
			t.Fatal(err)
		}
		if final["event"] != "FINAL" || final["state"] != "STARTED" {
			t.Fatal("actual synthetic transport was not recorded")
		}
	}
}

func (pg02DenyGuard) AuthorizeDispatch() error { return errors.New("fixture revoked") }

func TestPG02ProviderTransportActualRoundTrip(t *testing.T) {
	for _, kind := range []string{"started", "network_error", "fence_denied", "not_started", "repeated", "write_failure", "unsupported"} {
		t.Run(kind, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.Chmod(dir, 0700); err != nil {
				t.Fatal(err)
			}
			t.Setenv("CLEARAPI_PG02_TRANSPORT_DIR", dir)
			headers := http.Header{}
			headers.Set("X-ClearAPI-PG02-Request", "fixture-request")
			headers.Set("X-ClearAPI-PG02-Attempt", "fixture-attempt")
			model := "gpt-5.6-luna"
			if kind == "unsupported" {
				model = "other-model"
			}
			ctx := context.Background()
			if kind == "fence_denied" {
				ctx = coreexecutor.WithDispatchGuard(ctx, pg02DenyGuard{})
			}
			ctx, finish := PG02TransportContext(ctx, headers, model, "synthetic-account", 52)
			calls := 0
			client := NewUsageReporter(ctx, "codex", model, nil).TrackHTTPClient(&http.Client{Transport: roundTripFunc(func(r *http.Request) (*http.Response, error) {
				calls++
				if kind == "network_error" {
					return nil, errors.New("fixture network outcome unknown")
				}
				return &http.Response{StatusCode: 200, Header: http.Header{}, Body: io.NopCloser(strings.NewReader("fixture")), Request: r}, nil
			})})
			if kind == "write_failure" {
				r := ctx.Value(pg02TransportKey{}).(*pg02Transport)
				_ = r.file.Close()
			}
			if kind != "not_started" {
				req, e := http.NewRequestWithContext(ctx, "POST", "https://fixture.invalid/responses", nil)
				if e != nil {
					t.Fatal(e)
				}
				resp, _ := client.Do(req)
				if resp != nil {
					_ = resp.Body.Close()
				}
			}
			if kind == "repeated" {
				var wg sync.WaitGroup
				for range 8 {
					wg.Go(func() { pg02TransportStarted(ctx) })
				}
				wg.Wait()
			}
			finish()
			files, e := filepath.Glob(filepath.Join(dir, "*.jsonl"))
			if e != nil {
				t.Fatal(e)
			}
			if kind == "unsupported" {
				if len(files) != 0 {
					t.Fatal("unsupported path produced proof")
				}
				return
			}
			if len(files) != 1 {
				t.Fatal("receipt missing")
			}
			data, e := os.ReadFile(files[0])
			if e != nil {
				t.Fatal(e)
			}
			if strings.Contains(string(data), "synthetic-account") {
				t.Fatal("raw identity leaked")
			}
			lines := strings.Split(strings.TrimSpace(string(data)), "\n")
			var last map[string]any
			if e = json.Unmarshal([]byte(lines[len(lines)-1]), &last); e != nil {
				t.Fatal(e)
			}
			if kind == "write_failure" {
				if last["event"] == "FINAL" {
					t.Fatal("failed writer certified final receipt")
				}
				return
			}
			want := "STARTED"
			if kind == "not_started" || kind == "fence_denied" {
				want = "NOT_STARTED"
			}
			if kind == "repeated" {
				want = "UNKNOWN"
			}
			if last["state"] != want || last["request_id"] != "fixture-request" || last["attempt_id"] != "fixture-attempt" || last["account_generation"] != float64(52) {
				t.Fatalf("unexpected receipt: %+v", last)
			}
			if last["process_start_ticks"] == "" {
				t.Fatal("missing process binding")
			}
			if kind == "fence_denied" && calls != 0 {
				t.Fatal("revocation fence bypassed")
			}
		})
	}
}
