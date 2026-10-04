package auth

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"strings"
)

const poolCheckpointLimit = 4 * 1024 * 1024

type poolCheckpoint struct {
	GuardVersion int               `json:"guard_version"`
	ExecutorID   string            `json:"executor_id"`
	Revision     uint64            `json:"revision"`
	Digest       string            `json:"digest"`
	Trust        []PoolTrustRecord `json:"trust,omitempty"`
	Integrity    string            `json:"integrity,omitempty"`
}

func validPoolExecutorID(id string) bool {
	if id == "" || len(id) > 128 {
		return false
	}
	for _, character := range id {
		if !(character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9' || strings.ContainsRune("._-", character)) {
			return false
		}
	}
	return true
}

// ProvisionPoolCheckpoint is an explicit trusted provisioning operation.
// The request path never creates a missing journal or resets a saved floor.
func ProvisionPoolCheckpoint(path, executorID string) error {
	if !validPoolExecutorID(executorID) {
		return ErrPoolGuard
	}
	body, err := json.Marshal(poolCheckpoint{GuardVersion: PoolGuardVersion, ExecutorID: executorID})
	if err != nil {
		return ErrPoolGuard
	}
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return ErrPoolGuard
	}
	count, writeErr := file.Write(append(body, '\n'))
	syncErr := file.Sync()
	closeErr := file.Close()
	if writeErr != nil || count != len(body)+1 || syncErr != nil || closeErr != nil {
		return ErrPoolGuard
	}
	return nil
}

// readPoolCheckpoint validates the entire journal while the caller holds its OS lock.
func (guard *poolGuard) readPoolCheckpoint(file *os.File) (poolCheckpoint, int, error) {
	if _, err := file.Seek(0, io.SeekStart); err != nil {
		return poolCheckpoint{}, 0, ErrPoolGuard
	}
	data, err := io.ReadAll(io.LimitReader(file, poolCheckpointLimit+1))
	if err != nil || len(data) > poolCheckpointLimit || len(data) == 0 || data[len(data)-1] != '\n' {
		return poolCheckpoint{}, 0, ErrPoolGuard
	}
	var floor poolCheckpoint
	for index, line := range bytes.Split(bytes.TrimSuffix(data, []byte{'\n'}), []byte{'\n'}) {
		var item poolCheckpoint
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&item) != nil || item.GuardVersion != PoolGuardVersion || item.ExecutorID != guard.executorID {
			return floor, 0, ErrPoolGuard
		}
		var extra any
		if decoder.Decode(&extra) != io.EOF {
			return floor, 0, ErrPoolGuard
		}
		if index == 0 {
			if item.Revision != 0 || item.Digest != "" || len(item.Trust) != 0 {
				return floor, 0, ErrPoolGuard
			}
		} else {
			digest, err := hex.DecodeString(item.Digest)
			if err != nil || len(digest) != sha256.Size || item.Revision <= floor.Revision || !validPoolTrust(item) || item.Integrity != poolCheckpointIntegrity(item) {
				return floor, 0, ErrPoolGuard
			}
		}
		floor = item
	}
	if floor.Revision < guard.lastRevision || (floor.Revision == guard.lastRevision && floor.Digest != guard.lastDigest) {
		return floor, 0, ErrPoolGuard
	}
	return floor, len(data), nil
}

func poolRecordDigest(record *PoolGrantFile) string {
	body, err := json.Marshal(record)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])
}

func (guard *poolGuard) openPoolCheckpoint() (*os.File, error) {
	info, err := os.Lstat(guard.checkpoint)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > poolCheckpointLimit {
		return nil, ErrPoolGuard
	}
	file, err := os.OpenFile(guard.checkpoint, os.O_RDWR|os.O_APPEND, 0)
	if err != nil {
		return nil, ErrPoolGuard
	}
	if lockPoolCheckpoint(file) != nil {
		_ = file.Close()
		return nil, ErrPoolGuard
	}
	return file, nil
}

func (guard *poolGuard) appendPoolCheckpoint(file *os.File, size int, next poolCheckpoint) error {
	next.Integrity = poolCheckpointIntegrity(next)
	encoded, err := json.Marshal(next)
	if err != nil || size+len(encoded)+1 > poolCheckpointLimit {
		return ErrPoolGuard
	}
	count, err := file.Write(append(encoded, '\n'))
	if err != nil || count != len(encoded)+1 || file.Sync() != nil {
		return ErrPoolGuard
	}
	return nil
}

func (guard *poolGuard) installPoolCheckpoint(record poolCheckpoint) {
	guard.lastRevision, guard.lastDigest = record.Revision, record.Digest
	guard.trust = make(map[string]PoolTrustRecord, len(record.Trust))
	for _, trust := range record.Trust {
		guard.trust[trust.AuthID] = trust
	}
}

// Observing a new operator policy advances the 1A floor, but never promotes it.
// All previous trusted snapshots become pending; revoked tombstones survive.
func (guard *poolGuard) acceptCheckpoint(record *PoolGrantFile) (resultErr error) {
	guard.journalMu.Lock()
	defer guard.journalMu.Unlock()
	file, err := guard.openPoolCheckpoint()
	if err != nil {
		return err
	}
	defer func() {
		unlockPoolCheckpoint(file)
		if file.Close() != nil {
			guard.faulted.Store(true)
			resultErr = ErrPoolGuard
		}
	}()
	floor, size, err := guard.readPoolCheckpoint(file)
	if err != nil {
		return err
	}
	digest := poolRecordDigest(record)
	if digest == "" || record.Revision < floor.Revision || record.Revision == floor.Revision && digest != floor.Digest {
		return ErrPoolGuard
	}
	if record.Revision > floor.Revision {
		floor = poolCheckpoint{GuardVersion: PoolGuardVersion, ExecutorID: guard.executorID, Revision: record.Revision, Digest: digest, Trust: pendingPoolTrust(floor.Trust, record.Revision)}
		if err := guard.appendPoolCheckpoint(file, size, floor); err != nil {
			guard.faulted.Store(true)
			return err
		}
	}
	// Recovered complete records must also be synchronizable before use. A
	// prior uncertain write is never made usable just because it is readable.
	if err := file.Sync(); err != nil {
		guard.faulted.Store(true)
		return ErrPoolGuard
	}
	guard.installPoolCheckpoint(floor)
	return nil
}

func poolCheckpointIntegrity(record poolCheckpoint) string {
	record.Integrity = ""
	data, err := json.Marshal(record)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
