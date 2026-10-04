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
	GuardVersion int    `json:"guard_version"`
	ExecutorID   string `json:"executor_id"`
	Revision     uint64 `json:"revision"`
	Digest       string `json:"digest"`
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

// A complete, synced journal entry is required before a new grant is used.
// Torn writes and missing checkpoints fail closed instead of being repaired.
func (guard *poolGuard) acceptCheckpoint(record *PoolGrantFile) (resultErr error) {
	guard.journalMu.Lock()
	defer guard.journalMu.Unlock()
	info, err := os.Lstat(guard.checkpoint)
	if err != nil || !info.Mode().IsRegular() || info.Size() <= 0 || info.Size() > poolCheckpointLimit {
		return ErrPoolGuard
	}
	file, err := os.OpenFile(guard.checkpoint, os.O_RDWR|os.O_APPEND, 0)
	if err != nil {
		return ErrPoolGuard
	}
	defer func() {
		if file.Close() != nil {
			resultErr = ErrPoolGuard
		}
	}()
	if err := lockPoolCheckpoint(file); err != nil {
		return ErrPoolGuard
	}
	defer unlockPoolCheckpoint(file)
	data, err := io.ReadAll(io.LimitReader(file, poolCheckpointLimit+1))
	if err != nil || len(data) > poolCheckpointLimit || len(data) == 0 || data[len(data)-1] != '\n' {
		return ErrPoolGuard
	}
	var floor poolCheckpoint
	for index, line := range bytes.Split(bytes.TrimSuffix(data, []byte{'\n'}), []byte{'\n'}) {
		var item poolCheckpoint
		decoder := json.NewDecoder(bytes.NewReader(line))
		decoder.DisallowUnknownFields()
		if decoder.Decode(&item) != nil || item.GuardVersion != PoolGuardVersion || item.ExecutorID != guard.executorID {
			return ErrPoolGuard
		}
		var extra any
		if decoder.Decode(&extra) != io.EOF {
			return ErrPoolGuard
		}
		if index == 0 {
			if item.Revision != 0 || item.Digest != "" {
				return ErrPoolGuard
			}
		} else {
			digest, err := hex.DecodeString(item.Digest)
			if err != nil || len(digest) != sha256.Size || item.Revision <= floor.Revision {
				return ErrPoolGuard
			}
		}
		floor = item
	}
	body, err := json.Marshal(record)
	if err != nil {
		return ErrPoolGuard
	}
	sum := sha256.Sum256(body)
	digest := hex.EncodeToString(sum[:])
	if floor.Revision < guard.lastRevision || (floor.Revision == guard.lastRevision && floor.Digest != guard.lastDigest) {
		return ErrPoolGuard
	}
	if record.Revision < floor.Revision || record.Revision == floor.Revision && digest != floor.Digest {
		return ErrPoolGuard
	}
	if record.Revision > floor.Revision {
		next := poolCheckpoint{GuardVersion: PoolGuardVersion, ExecutorID: guard.executorID, Revision: record.Revision, Digest: digest}
		encoded, err := json.Marshal(next)
		if err != nil || len(data)+len(encoded)+1 > poolCheckpointLimit {
			return ErrPoolGuard
		}
		count, err := file.Write(append(encoded, '\n'))
		if err != nil || count != len(encoded)+1 || file.Sync() != nil {
			return ErrPoolGuard
		}
	}
	guard.lastRevision, guard.lastDigest = record.Revision, digest
	return nil
}
