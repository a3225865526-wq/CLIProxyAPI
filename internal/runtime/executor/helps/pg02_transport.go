package helps

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/google/uuid"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/buildinfo"
)

type pg02TransportKey struct{}

var pg02ProcessEpoch = uuid.NewString()
var pg02ID = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,160}$`)

// pg02Transport journals invocation evidence only. It cannot authorize replay,
// certify provider receipt, or change authentication/usage/settlement behavior.
type pg02Transport struct {
	mu       sync.Mutex
	file     *os.File
	healthy  bool
	sequence int
	started  bool
	event    map[string]any
}

func PG02TransportContext(ctx context.Context, headers http.Header, model, accountID string, generation uint64) (context.Context, func()) {
	// The lease-bound writer supersedes the legacy unbound probe observer.
	if os.Getenv("CLEARAPI_PG02_RECEIPT_DIR") != "" {
		return ctx, func() {}
	}
	dir := os.Getenv("CLEARAPI_PG02_TRANSPORT_DIR")
	requestID, attemptID := headers.Get("X-ClearAPI-PG02-Request"), headers.Get("X-ClearAPI-PG02-Attempt")
	if dir == "" || model != "gpt-5.6-luna" || !pg02ID.MatchString(requestID) || !pg02ID.MatchString(attemptID) || accountID == "" {
		return ctx, func() {}
	}
	st, err := os.Lstat(dir)
	if err != nil || !st.IsDir() || st.Mode().Perm() != 0700 {
		return ctx, func() {}
	}
	// No overwrite or reuse across retries, concurrent executions or restarts.
	file, err := os.OpenFile(filepath.Join(dir, "pg02-"+uuid.NewString()+".jsonl"), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	if err != nil {
		return ctx, func() {}
	}
	accountHash := sha256.Sum256([]byte(accountID))
	receipt := &pg02Transport{file: file, healthy: true, event: map[string]any{
		"schema": 1, "request_id": requestID, "attempt_id": attemptID, "canonical_model": model,
		"account_ref": hex.EncodeToString(accountHash[:]), "account_generation": generation,
		"process_epoch": pg02ProcessEpoch, "process_id": os.Getpid(), "process_start_ticks": pg02StartTicks(),
		"executor_binary_sha256": pg02BinarySHA(),
		"executor_version":       buildinfo.Version, "executor_commit": buildinfo.Commit, "provider": "codex", "path": "HTTP_NON_STREAM",
		"receipt_id": uuid.NewString(),
	}}
	receipt.mu.Lock()
	receipt.write("BEGIN", "UNKNOWN")
	receipt.mu.Unlock()
	return context.WithValue(ctx, pg02TransportKey{}, receipt), func() {
		receipt.mu.Lock()
		defer receipt.mu.Unlock()
		state := "NOT_STARTED"
		if receipt.started {
			state = "STARTED"
		}
		if !receipt.healthy || receipt.event["process_start_ticks"] == "" || receipt.event["executor_binary_sha256"] == "" {
			state = "UNKNOWN"
		}
		receipt.write("FINAL", state)
		_ = receipt.file.Close()
	}
}

func pg02StartTicks() string {
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return ""
	}
	at := strings.LastIndex(string(data), ")")
	if at < 0 {
		return ""
	}
	fields := strings.Fields(string(data)[at+1:])
	if len(fields) < 20 {
		return ""
	}
	return fields[19]
}

func (r *pg02Transport) write(event, state string) {
	r.sequence++
	r.event["sequence"], r.event["event"], r.event["state"] = r.sequence, event, state
	data, err := json.Marshal(r.event)
	if err == nil {
		_, err = r.file.Write(append(data, '\n'))
	}
	if err == nil {
		err = r.file.Sync()
	}
	if err != nil {
		r.healthy = false
	}
}

// Called only after BeforeUpstreamDispatch succeeds and immediately before
// the actual HTTP RoundTripper. STARTED means HTTP operation initiation, never
// completed wire write, remote acceptance, or billable work.
func pg02TransportStarted(ctx context.Context) {
	r, _ := ctx.Value(pg02TransportKey{}).(*pg02Transport)
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.started {
		r.healthy = false
		r.write("REPEATED_BOUNDARY", "UNKNOWN")
		return
	}
	r.started = true
	r.write("STARTED", "STARTED")
}

var pg02BinaryOnce sync.Once
var pg02BinaryHash string

func pg02BinarySHA() string {
	pg02BinaryOnce.Do(func() {
		file, err := os.Open("/proc/self/exe")
		if err != nil {
			return
		}
		defer file.Close()
		digest := sha256.New()
		if _, err = io.Copy(digest, file); err == nil {
			pg02BinaryHash = hex.EncodeToString(digest.Sum(nil))
		}
	})
	return pg02BinaryHash
}
