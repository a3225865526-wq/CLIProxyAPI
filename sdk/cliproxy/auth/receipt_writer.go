package auth

import (
	"bytes"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"

	"github.com/router-for-me/CLIProxyAPI/v8/internal/buildinfo"
	"github.com/router-for-me/CLIProxyAPI/v8/internal/logging"
	"github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/usage"
)

const receiptDirEnv = "CLEARAPI_PG02_RECEIPT_DIR"

var receiptIDPattern = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,160}$`)

func validReceiptID(value string) bool { return receiptIDPattern.MatchString(value) }

var receiptProcessEpoch = func() string {
	value := make([]byte, 16)
	if _, err := rand.Read(value); err != nil {
		return ""
	}
	return hex.EncodeToString(value)
}()

type receiptWriter struct {
	dir            string
	mu             sync.Mutex
	processID      int
	processEpoch   string
	startTicks     string
	binarySHA      string
	executorVer    string
	executorCommit string
	faulted        atomic.Bool
}

type receiptEvent struct {
	AccountGeneration uint64           `json:"account_generation"`
	AccountRef        string           `json:"account_ref"`
	AttemptID         string           `json:"attempt_id"`
	CanonicalModel    string           `json:"canonical_model"`
	Event             string           `json:"event"`
	ExecutorBinarySHA string           `json:"executor_binary_sha256"`
	ExecutorCommit    string           `json:"executor_commit"`
	ExecutorVersion   string           `json:"executor_version"`
	Path              string           `json:"path"`
	ProcessEpoch      string           `json:"process_epoch"`
	ProcessID         int              `json:"process_id"`
	ProcessStartTicks string           `json:"process_start_ticks"`
	Provider          string           `json:"provider"`
	ReceiptID         string           `json:"receipt_id"`
	RequestID         string           `json:"request_id"`
	Schema            int              `json:"schema"`
	Sequence          int              `json:"sequence"`
	State             string           `json:"state"`
	SSE               *sseReceiptFinal `json:"sse,omitempty"`
	// Images carries the schema-3 image business result. It contains counts and
	// references only; image bytes are persisted separately by imagesResultStore.
	Images            *imagesReceiptFinal `json:"images,omitempty"`
	AccountEvidenceID string              `json:"account_evidence_id,omitempty"`
	PreviousReceiptID string              `json:"previous_receipt_id,omitempty"`
}

// SSE evidence is versioned separately; schema-1 bytes and hashes are unchanged.
type sseReceiptFinal struct {
	DispatchState string               `json:"dispatch_state"`
	ResultState   string               `json:"result_state"`
	ResponseID    string               `json:"response_id"`
	TerminalType  string               `json:"terminal_type"`
	EndReason     string               `json:"end_reason"`
	Usage         *usage.CodexMetering `json:"usage"`
	SHA256        string               `json:"sha256,omitempty"`
}

func newReceiptWriter() (*receiptWriter, error) {
	dir := strings.TrimSpace(os.Getenv(receiptDirEnv))
	if dir == "" {
		return nil, nil
	}
	directory, err := openReceiptDirectory(dir)
	if err != nil {
		return nil, err
	}
	if err := directory.Close(); err != nil {
		return nil, err
	}
	binary, err := os.Open("/proc/self/exe")
	if err != nil {
		return nil, fmt.Errorf("read executor binary: %w", err)
	}
	digest := sha256.New()
	_, readErr := io.Copy(digest, binary)
	closeErr := binary.Close()
	if readErr != nil || closeErr != nil {
		return nil, errors.New("cannot hash running executor binary")
	}
	ticks := processStartTicks()
	if ticks == "" || receiptProcessEpoch == "" {
		return nil, errors.New("running process identity unavailable")
	}
	epoch := receiptProcessEpoch
	if os.Getenv("CLEARAPI_PG02_RESPONSES_SSE") == "true" {
		epoch = os.Getenv("CLEARAPI_PG02_PROCESS_EPOCH")
		decoded, err := hex.DecodeString(epoch)
		if err != nil || len(decoded) != 16 || hex.EncodeToString(decoded) != epoch {
			return nil, errors.New("SSE requires an independently provisioned process epoch")
		}
	}
	return &receiptWriter{dir: dir, processID: os.Getpid(), processEpoch: epoch, startTicks: ticks, binarySHA: hex.EncodeToString(digest.Sum(nil)), executorVer: buildinfo.Version, executorCommit: buildinfo.Commit}, nil
}

func processStartTicks() string {
	data, err := os.ReadFile("/proc/self/stat")
	if err != nil {
		return ""
	}
	at := strings.LastIndex(string(data), ")")
	if at < 0 {
		return ""
	}
	fields := strings.Fields(string(data)[at+1:])
	if len(fields) <= 19 {
		return ""
	}
	return fields[19]
}

func (w *receiptWriter) write(event receiptEvent) (resultErr error) {
	if w == nil {
		return nil
	}
	data, err := json.Marshal(event)
	if err != nil {
		return err
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	defer func() {
		if resultErr != nil {
			w.faulted.Store(true)
		}
	}()
	if w.faulted.Load() {
		return fmt.Errorf("receipt storage faulted: %w", ErrPoolGuard)
	}
	directory, err := openReceiptDirectory(w.dir)
	if err != nil {
		return err
	}
	defer func() {
		if errClose := directory.Close(); errClose != nil && resultErr == nil {
			resultErr = errClose
			w.faulted.Store(true)
		}
	}()
	name := event.ReceiptID + ".jsonl"
	if filepath.Base(name) != name {
		return errors.New("invalid receipt identifier")
	}
	file, err := openReceiptFile(directory, name, event.Event == "BEGIN")
	if err != nil {
		return err
	}
	defer func() {
		if errClose := file.Close(); errClose != nil && resultErr == nil {
			resultErr = errClose
			w.faulted.Store(true)
		}
	}()
	prior, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil || len(prior) > 65536 {
		return errors.New("receipt read failed or oversized")
	}
	if event.Event == "BEGIN" {
		if len(prior) != 0 || event.Sequence != 1 {
			return errors.New("receipt already exists")
		}
	} else {
		if len(prior) == 0 || prior[len(prior)-1] != '\n' {
			return errors.New("receipt incomplete")
		}
		lines := bytes.Split(bytes.TrimSuffix(prior, []byte{'\n'}), []byte{'\n'})
		if len(lines) != event.Sequence-1 {
			return errors.New("receipt sequence mismatch")
		}
		for index, line := range lines {
			previous := event
			previous.SSE, previous.Images = nil, nil
			previous.Sequence = index + 1
			previous.Event, previous.State = "BEGIN", "UNKNOWN"
			if index == 1 {
				previous.Event, previous.State = "STARTED", "STARTED"
			}
			expected, _ := json.Marshal(previous)
			if !bytes.Equal(line, expected) {
				return errors.New("receipt prior record changed")
			}
		}
	}
	if count, errWrite := file.Write(append(data, '\n')); errWrite != nil || count != len(data)+1 {
		return errors.New("receipt write failed or short")
	}
	if err = file.Sync(); err != nil {
		return err
	}
	return directory.Sync()
}

func (w *receiptWriter) event(lease *poolLease, event, state string, sequence int) receiptEvent {
	requestID := lease.receiptRequestID
	if requestID == "" {
		requestID = logging.GetRequestID(lease.ctx)
	}
	if requestID == "" {
		requestID = "pool-" + strconv.FormatUint(lease.RequestID, 10)
	}
	account := sha256.Sum256([]byte(lease.AuthID))
	attemptID := lease.attemptID
	if attemptID == "" {
		attemptID = strconv.FormatUint(lease.RequestID, 10)
	}
	result := receiptEvent{AccountGeneration: lease.Generation, AccountRef: hex.EncodeToString(account[:]), AttemptID: attemptID, CanonicalModel: lease.req.Model, Event: event, ExecutorBinarySHA: w.binarySHA, ExecutorCommit: w.executorCommit, ExecutorVersion: w.executorVer, Path: "HTTP_NON_STREAM", ProcessEpoch: w.processEpoch, ProcessID: w.processID, ProcessStartTicks: w.startTicks, Provider: lease.Provider, ReceiptID: lease.receiptID, RequestID: requestID, Schema: 1, Sequence: sequence, State: state}
	if lease.receiptSSE {
		result.Path, result.Schema = "HTTP_RESPONSES_SSE", 2
		result.PreviousReceiptID = lease.previousReceiptID
		// The Gateway attempt identifies the channel send. An unstarted account
		// rejection is not a second channel attempt; it has its own durable ID.
		digest := sha256.Sum256([]byte(requestID + "\n" + attemptID + "\n" + result.AccountRef + "\n" + strconv.FormatUint(lease.Generation, 10)))
		result.AccountEvidenceID = hex.EncodeToString(digest[:])
	}
	if lease.receiptImages {
		result.Path, result.Schema = "HTTP_IMAGES_JSON", 3
		// Image receipts key the evidence on the Gateway-declared attempt so a
		// duplicate FINAL for the same attempt can be recognised as a replay.
		digest := sha256.Sum256([]byte(requestID + "\n" + attemptID + "\n" + result.AccountRef + "\n" + strconv.FormatUint(lease.Generation, 10)))
		result.AccountEvidenceID = hex.EncodeToString(digest[:])
	}
	return result
}

// The parent is the exact record minted by this writer after a durable local
// rejection. Re-read it before B starts; memory provenance alone is insufficient.
func (w *receiptWriter) verifyZeroDispatchParent(final receiptEvent) (resultErr error) {
	return w.verifyZeroDispatchRecord(final, false)
}

func (w *receiptWriter) verifyZeroDispatchRecord(final receiptEvent, chainValidated bool) (resultErr error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	defer func() {
		if resultErr != nil {
			w.faulted.Store(true)
		}
	}()
	if w.faulted.Load() || final.Schema != 2 || final.Path != "HTTP_RESPONSES_SSE" || final.State != "NOT_STARTED" || final.Sequence != 2 || final.Event != "FINAL" || (!chainValidated && final.PreviousReceiptID != "") || final.SSE == nil || final.SSE.DispatchState != "NOT_STARTED" || final.SSE.ResultState != "FAILED" || final.SSE.EndReason != "account_credential_locally_unavailable" || final.ProcessEpoch != w.processEpoch || final.ExecutorBinarySHA != w.binarySHA || final.ProcessID != w.processID || final.ProcessStartTicks != w.startTicks || !validReceiptID(final.ReceiptID) {
		return ErrPoolGuard
	}
	directory, err := openReceiptDirectory(w.dir)
	if err != nil {
		return err
	}
	defer func() {
		if err := directory.Close(); err != nil && resultErr == nil {
			resultErr = err
		}
	}()
	file, err := openReceiptFile(directory, final.ReceiptID+".jsonl", false)
	if err != nil {
		return err
	}
	defer func() {
		if err := file.Close(); err != nil && resultErr == nil {
			resultErr = err
		}
	}()
	data, err := io.ReadAll(io.LimitReader(file, 65537))
	if err != nil || len(data) > 65536 {
		return ErrPoolGuard
	}
	begin := final
	begin.Event, begin.State, begin.Sequence, begin.SSE = "BEGIN", "UNKNOWN", 1, nil
	first, err := json.Marshal(begin)
	if err != nil {
		return err
	}
	last, err := json.Marshal(final)
	if err != nil {
		return err
	}
	expected := append(append(append(first, '\n'), last...), '\n')
	if !bytes.Equal(data, expected) {
		return ErrPoolGuard
	}
	return nil
}

// readAttempt returns every durable event for one request/attempt pair. The
// receipt file name is derived from the same deterministic identity the lease
// uses, so a restart or a query never depends on in-memory state.
func (w *receiptWriter) readAttempt(requestID, attemptID string) ([]map[string]any, error) {
	if w == nil {
		return nil, ErrPoolGuard
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.faulted.Load() {
		return nil, ErrPoolGuard
	}
	directory, err := openReceiptDirectory(w.dir)
	if err != nil {
		return nil, err
	}
	defer func() { _ = directory.Close() }()
	entries, err := directory.Readdirnames(4096)
	if err != nil {
		return nil, err
	}
	for _, name := range entries {
		if !strings.HasSuffix(name, ".jsonl") {
			continue
		}
		file, err := openReceiptFile(directory, name, false)
		if err != nil {
			continue
		}
		data, readErr := io.ReadAll(io.LimitReader(file, 1<<20))
		_ = file.Close()
		if readErr != nil {
			continue
		}
		matched := make([]map[string]any, 0, 3)
		matchedAll := true
		for _, line := range bytes.Split(bytes.TrimSpace(data), []byte{'\n'}) {
			if len(line) == 0 {
				continue
			}
			var event map[string]any
			if json.Unmarshal(line, &event) != nil {
				matchedAll = false
				break
			}
			eventRequestID, _ := event["request_id"].(string)
			eventAttemptID, _ := event["attempt_id"].(string)
			if eventRequestID != requestID || eventAttemptID != attemptID {
				matchedAll = false
				break
			}
			matched = append(matched, event)
		}
		if matchedAll && len(matched) > 0 {
			return matched, nil
		}
	}
	return nil, ErrPoolGuard
}

func (w *receiptWriter) begin(lease *poolLease) error {
	return w.write(w.event(lease, "BEGIN", "UNKNOWN", 1))
}

func (w *receiptWriter) started(lease *poolLease) error {
	return w.write(w.event(lease, "STARTED", "STARTED", 2))
}

func (w *receiptWriter) final(lease *poolLease, state string) error {
	sequence := 2
	if state == "STARTED" {
		sequence = 3
	}
	return w.write(w.event(lease, "FINAL", state, sequence))
}
