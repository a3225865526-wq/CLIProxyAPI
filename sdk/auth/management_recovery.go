package auth

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

const managementRecoveryWALSuffix = ".management-recovery.wal"

type managementRecoveryRecord struct {
	Version          int                              `json:"version"`
	OpID             string                           `json:"op_id"`
	AuthID           string                           `json:"auth_id"`
	CredentialDigest string                           `json:"credential_digest"`
	Generation       uint64                           `json:"generation"`
	Revision         uint64                           `json:"revision"`
	State            coreauth.ManagementRecoveryState `json:"state"`
	TargetDisabled   bool                             `json:"target_disabled"`
	Digest           string                           `json:"digest"`
}

type managementRecoveryRecordUnsigned struct {
	Version          int                              `json:"version"`
	OpID             string                           `json:"op_id"`
	AuthID           string                           `json:"auth_id"`
	CredentialDigest string                           `json:"credential_digest"`
	Generation       uint64                           `json:"generation"`
	Revision         uint64                           `json:"revision"`
	State            coreauth.ManagementRecoveryState `json:"state"`
	TargetDisabled   bool                             `json:"target_disabled"`
}

func managementRecoveryPath(authPath string) string {
	return authPath + managementRecoveryWALSuffix
}

func (r managementRecoveryRecord) unsigned() managementRecoveryRecordUnsigned {
	return managementRecoveryRecordUnsigned{
		Version: r.Version, OpID: r.OpID, AuthID: r.AuthID,
		CredentialDigest: r.CredentialDigest, Generation: r.Generation,
		Revision: r.Revision, State: r.State, TargetDisabled: r.TargetDisabled,
	}
}

func (r managementRecoveryRecord) valid() bool {
	if r.Version != 1 || strings.TrimSpace(r.OpID) == "" || strings.TrimSpace(r.AuthID) == "" ||
		r.CredentialDigest == "" || r.Generation == 0 || r.Revision == 0 || r.TargetDisabled ||
		(r.State != coreauth.ManagementRecoveryPrepared && r.State != coreauth.ManagementRecoveryCommitted) {
		return false
	}
	digest, errDigest := hex.DecodeString(r.CredentialDigest)
	if errDigest != nil || len(digest) != sha256.Size {
		return false
	}
	payload, errMarshal := json.Marshal(r.unsigned())
	if errMarshal != nil {
		return false
	}
	sum := sha256.Sum256(payload)
	return r.Digest == hex.EncodeToString(sum[:])
}

func newManagementRecoveryRecord(op coreauth.ManagementRecoveryOperation) (managementRecoveryRecord, error) {
	record := managementRecoveryRecord{
		Version: 1, OpID: op.OpID, AuthID: op.AuthID,
		CredentialDigest: op.CredentialDigest, Generation: op.Generation,
		Revision: op.Revision, State: op.State, TargetDisabled: op.TargetDisabled,
	}
	if !record.validWithoutDigest() {
		return managementRecoveryRecord{}, fmt.Errorf("invalid recovery operation")
	}
	payload, errMarshal := json.Marshal(record.unsigned())
	if errMarshal != nil {
		return managementRecoveryRecord{}, errMarshal
	}
	sum := sha256.Sum256(payload)
	record.Digest = hex.EncodeToString(sum[:])
	return record, nil
}

func (r managementRecoveryRecord) validWithoutDigest() bool {
	if r.Version != 1 || strings.TrimSpace(r.OpID) == "" || strings.TrimSpace(r.AuthID) == "" ||
		r.Generation == 0 || r.Revision == 0 || r.TargetDisabled ||
		(r.State != coreauth.ManagementRecoveryPrepared && r.State != coreauth.ManagementRecoveryCommitted) {
		return false
	}
	digest, errDigest := hex.DecodeString(r.CredentialDigest)
	return errDigest == nil && len(digest) == sha256.Size
}

func sameManagementRecoveryRecord(r managementRecoveryRecord, op coreauth.ManagementRecoveryOperation) bool {
	return r.valid() && r.OpID == op.OpID && r.AuthID == op.AuthID &&
		r.CredentialDigest == op.CredentialDigest && r.Generation == op.Generation &&
		r.Revision == op.Revision && r.TargetDisabled == op.TargetDisabled
}

func (s *FileTokenStore) PrepareManagementRecovery(_ context.Context, auth *coreauth.Auth, op coreauth.ManagementRecoveryOperation) error {
	if errValidate := validateManagementRecoveryAuth(auth, op); errValidate != nil {
		return errValidate
	}
	path, errPath := s.resolveRecoveryAuthPath(auth)
	if errPath != nil {
		return errPath
	}
	if auth.Storage != nil || coreauth.IsPluginVirtualAuth(auth) || coreauth.IsConfigAPIKeyAuth(auth) {
		return fmt.Errorf("management recovery: unsupported persistence path")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	walPath := managementRecoveryPath(path)
	existing, errExisting := readManagementRecoveryRecord(walPath)
	if errExisting != nil && !os.IsNotExist(errExisting) {
		return errExisting
	}
	metadata, errRead := readRecoveryMetadata(path)
	if errRead != nil {
		return errRead
	}
	if !metadataBoolValid(metadata, "disabled", true) || !metadataBoolValid(metadata, coreauth.ManagementDisabledKey, true) {
		if errExisting == nil && existing.State == coreauth.ManagementRecoveryPrepared {
			return &coreauth.ManagementRecoveryOutcomeError{Status: "UNKNOWN", OpID: existing.OpID, Err: fmt.Errorf("previous recovery operation remains unresolved")}
		}
		return fmt.Errorf("management recovery: source is not durably isolated")
	}
	loaded := auth.Clone()
	loaded.Metadata = metadata
	if coreauth.PoolCredentialDigest(loaded) != op.CredentialDigest {
		return fmt.Errorf("management recovery: source credential identity mismatch")
	}
	if errExisting == nil {
		if sameManagementRecoveryRecord(existing, op) {
			return nil
		}
		// A currently durable management disable fences every previous
		// operation. It is therefore safe to supersede an older PREPARED or
		// COMMITTED record before beginning a new authorized recovery.
		if existing.State != coreauth.ManagementRecoveryPrepared && existing.State != coreauth.ManagementRecoveryCommitted {
			return fmt.Errorf("management recovery: existing operation mismatch")
		}
	}
	record, errRecord := newManagementRecoveryRecord(op)
	if errRecord != nil {
		return errRecord
	}
	return writeManagementRecoveryRecord(walPath, record)
}

func (s *FileTokenStore) CommitManagementRecovery(_ context.Context, auth *coreauth.Auth, op coreauth.ManagementRecoveryOperation) (coreauth.ManagementRecoveryState, error) {
	if errValidate := validateManagementRecoveryAuth(auth, op); errValidate != nil {
		return "", errValidate
	}
	path, errPath := s.resolveRecoveryAuthPath(auth)
	if errPath != nil {
		return "", errPath
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, errRecord := readManagementRecoveryRecord(managementRecoveryPath(path))
	if errRecord != nil {
		return "", errRecord
	}
	if !sameManagementRecoveryRecord(record, op) || record.State != coreauth.ManagementRecoveryPrepared {
		if sameManagementRecoveryRecord(record, op) && record.State == coreauth.ManagementRecoveryCommitted {
			if !managementPersistenceQualified() {
				return "", fmt.Errorf("management recovery: durable persistence is not qualified on this platform")
			}
			if errSync := syncManagementDirectory(filepath.Dir(path)); errSync != nil {
				return "", fmt.Errorf("management recovery: committed WAL durability is unknown: %w", errSync)
			}
			record, errRecord = readManagementRecoveryRecord(managementRecoveryPath(path))
			if errRecord != nil || !sameManagementRecoveryRecord(record, op) || record.State != coreauth.ManagementRecoveryCommitted {
				return "", fmt.Errorf("management recovery: committed WAL could not be reverified")
			}
			if errAccount := verifyRecoveryAccount(path, auth, op); errAccount != nil {
				return "", errAccount
			}
			return record.State, nil
		}
		return "", fmt.Errorf("management recovery: PREPARED record mismatch")
	}
	if errAccount := verifyRecoveryAccount(path, auth, op); errAccount != nil {
		return "", errAccount
	}
	metadata, errMetadata := readRecoveryMetadata(path)
	if errMetadata != nil || metadataString(metadata, coreauth.RecoveryStateKey) != string(coreauth.ManagementRecoveryPrepared) {
		return "", fmt.Errorf("management recovery: account is not PREPARED")
	}
	record.State = coreauth.ManagementRecoveryCommitted
	payload, errMarshal := json.Marshal(record.unsigned())
	if errMarshal != nil {
		return "", errMarshal
	}
	sum := sha256.Sum256(payload)
	record.Digest = hex.EncodeToString(sum[:])
	if errWrite := writeManagementRecoveryRecord(managementRecoveryPath(path), record); errWrite != nil {
		return record.State, errWrite
	}
	return record.State, nil
}

func (s *FileTokenStore) VerifyManagementRecovery(_ context.Context, auth *coreauth.Auth, op coreauth.ManagementRecoveryOperation) (coreauth.ManagementRecoveryState, error) {
	if errValidate := validateManagementRecoveryAuth(auth, op); errValidate != nil {
		return "", errValidate
	}
	path, errPath := s.resolveRecoveryAuthPath(auth)
	if errPath != nil {
		return "", errPath
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	record, errRecord := readManagementRecoveryRecord(managementRecoveryPath(path))
	if errRecord != nil {
		return "", errRecord
	}
	if !sameManagementRecoveryRecord(record, op) {
		return "", fmt.Errorf("management recovery: record identity mismatch")
	}
	if record.State == coreauth.ManagementRecoveryPrepared {
		metadata, errRead := readRecoveryMetadata(path)
		if errRead != nil {
			return "", errRead
		}
		if metadataString(metadata, coreauth.RecoveryOpIDKey) == op.OpID &&
			metadataUint64(metadata, coreauth.RecoveryGenerationKey) == op.Generation &&
			metadataUint64(metadata, coreauth.RecoveryRevisionKey) == op.Revision &&
			metadataBoolValid(metadata, "disabled", false) &&
			metadataBoolValid(metadata, coreauth.ManagementDisabledKey, false) {
			return record.State, fmt.Errorf("management recovery: account write outcome is ambiguous")
		}
		if !metadataBoolValid(metadata, "disabled", true) || !metadataBoolValid(metadata, coreauth.ManagementDisabledKey, true) {
			return "", fmt.Errorf("management recovery: PREPARED account marker mismatch")
		}
	}
	if record.State == coreauth.ManagementRecoveryCommitted {
		if !managementPersistenceQualified() {
			return "", fmt.Errorf("management recovery: durable persistence is not qualified on this platform")
		}
		if errSync := syncManagementDirectory(filepath.Dir(path)); errSync != nil {
			return "", fmt.Errorf("management recovery: committed WAL durability is unknown: %w", errSync)
		}
		record, errRecord = readManagementRecoveryRecord(managementRecoveryPath(path))
		if errRecord != nil || !sameManagementRecoveryRecord(record, op) || record.State != coreauth.ManagementRecoveryCommitted {
			return "", fmt.Errorf("management recovery: committed WAL could not be reverified")
		}
		if errAccount := verifyRecoveryAccount(path, auth, op); errAccount != nil {
			return "", errAccount
		}
	}
	return record.State, nil
}

func validateManagementRecoveryAuth(auth *coreauth.Auth, op coreauth.ManagementRecoveryOperation) error {
	if auth == nil || auth.ID == "" || op.OpID == "" || op.AuthID != auth.ID || op.TargetDisabled ||
		op.State != coreauth.ManagementRecoveryPrepared ||
		op.Generation == 0 || op.Revision == 0 || op.CredentialDigest == "" ||
		coreauth.PoolCredentialDigest(auth) != op.CredentialDigest {
		return fmt.Errorf("management recovery: invalid identity or version binding")
	}
	return nil
}

func (s *FileTokenStore) resolveRecoveryAuthPath(auth *coreauth.Auth) (string, error) {
	if auth == nil || auth.Storage != nil || coreauth.IsPluginVirtualAuth(auth) || coreauth.IsConfigAPIKeyAuth(auth) {
		return "", fmt.Errorf("management recovery: unsupported persistence path")
	}
	return s.resolveAuthPath(auth)
}

func readRecoveryMetadata(path string) (map[string]any, error) {
	data, errRead := os.ReadFile(path)
	if errRead != nil {
		return nil, errRead
	}
	metadata := make(map[string]any)
	if errUnmarshal := json.Unmarshal(data, &metadata); errUnmarshal != nil {
		return nil, errUnmarshal
	}
	return metadata, nil
}

func readManagementRecoveryRecord(path string) (managementRecoveryRecord, error) {
	data, errRead := os.ReadFile(path)
	if errRead != nil {
		return managementRecoveryRecord{}, errRead
	}
	var record managementRecoveryRecord
	if errUnmarshal := json.Unmarshal(data, &record); errUnmarshal != nil || !record.valid() {
		if errUnmarshal != nil {
			return managementRecoveryRecord{}, errUnmarshal
		}
		return managementRecoveryRecord{}, fmt.Errorf("management recovery: invalid WAL record")
	}
	return record, nil
}

func writeManagementRecoveryRecord(path string, record managementRecoveryRecord) error {
	if !managementPersistenceQualified() {
		return fmt.Errorf("management recovery: durable persistence is not qualified on this platform")
	}
	data, errMarshal := json.Marshal(record)
	if errMarshal != nil {
		return errMarshal
	}
	return writeAuthJSONDurable(path, data)
}

func enforceRecoveryAdmission(auth *coreauth.Auth, path string) {
	if auth == nil || auth.Metadata == nil {
		return
	}
	_, hasOp := auth.Metadata[coreauth.RecoveryOpIDKey]
	_, hasGeneration := auth.Metadata[coreauth.RecoveryGenerationKey]
	_, hasRevision := auth.Metadata[coreauth.RecoveryRevisionKey]
	_, hasState := auth.Metadata[coreauth.RecoveryStateKey]
	walPath := managementRecoveryPath(path)
	if !hasOp && !hasGeneration && !hasRevision && !hasState {
		if _, errStat := os.Stat(walPath); errStat == nil {
			quarantineRecoveryAuth(auth)
		}
		return
	}
	opID := metadataString(auth.Metadata, coreauth.RecoveryOpIDKey)
	generation := metadataUint64(auth.Metadata, coreauth.RecoveryGenerationKey)
	revision := metadataUint64(auth.Metadata, coreauth.RecoveryRevisionKey)
	state, _ := auth.Metadata[coreauth.RecoveryStateKey].(string)
	if opID == "" || generation == 0 || revision == 0 ||
		(state != string(coreauth.ManagementRecoveryPrepared) && state != string(coreauth.ManagementRecoveryCommitted)) {
		quarantineRecoveryAuth(auth)
		return
	}
	record, errRecord := readManagementRecoveryRecord(walPath)
	if errRecord != nil || record.AuthID != auth.ID || record.OpID != opID ||
		record.CredentialDigest != coreauth.PoolCredentialDigest(auth) || record.Generation != generation ||
		record.Revision != revision || record.TargetDisabled || record.State != coreauth.ManagementRecoveryCommitted ||
		!metadataBoolValid(auth.Metadata, "disabled", false) || !metadataBoolValid(auth.Metadata, coreauth.ManagementDisabledKey, false) {
		quarantineRecoveryAuth(auth)
		return
	}
	// The WAL is the durable commit proof. Keep the marker in memory aligned
	// with that proof without rewriting the source file during startup.
	auth.Metadata[coreauth.RecoveryStateKey] = string(coreauth.ManagementRecoveryCommitted)
	auth.Generation = generation
}

// EnforceManagementRecoveryAdmission applies the FileStore recovery proof
// before a watcher-synthesized auth can be registered by the manager.
func EnforceManagementRecoveryAdmission(auth *coreauth.Auth, path string) {
	enforceRecoveryAdmission(auth, path)
}

func quarantineRecoveryAuth(auth *coreauth.Auth) {
	auth.Disabled = true
	auth.Status = coreauth.StatusDisabled
	if auth.Metadata == nil {
		auth.Metadata = make(map[string]any)
	}
	auth.Metadata["disabled"] = true
	auth.Metadata[coreauth.ManagementDisabledKey] = true
}

func verifyRecoveryAccount(path string, auth *coreauth.Auth, op coreauth.ManagementRecoveryOperation) error {
	metadata, errRead := readRecoveryMetadata(path)
	if errRead != nil {
		return errRead
	}
	if metadataString(metadata, coreauth.RecoveryOpIDKey) != op.OpID ||
		metadataUint64(metadata, coreauth.RecoveryGenerationKey) != op.Generation ||
		metadataUint64(metadata, coreauth.RecoveryRevisionKey) != op.Revision {
		return fmt.Errorf("management recovery: account marker mismatch")
	}
	state := metadataString(metadata, coreauth.RecoveryStateKey)
	if state != string(coreauth.ManagementRecoveryPrepared) && state != string(coreauth.ManagementRecoveryCommitted) {
		return fmt.Errorf("management recovery: account state marker mismatch")
	}
	if !metadataBoolValid(metadata, "disabled", false) || !metadataBoolValid(metadata, coreauth.ManagementDisabledKey, false) {
		return fmt.Errorf("management recovery: account isolation marker mismatch")
	}
	loaded := auth.Clone()
	loaded.Metadata = metadata
	if coreauth.PoolCredentialDigest(loaded) != op.CredentialDigest {
		return fmt.Errorf("management recovery: account credential mismatch")
	}
	return nil
}

func metadataString(metadata map[string]any, key string) string {
	value, _ := metadata[key].(string)
	return strings.TrimSpace(value)
}

func metadataBoolValue(metadata map[string]any, key string) (bool, bool) {
	value, ok := metadata[key].(bool)
	return value, ok
}

func metadataBoolValid(metadata map[string]any, key string, expected bool) bool {
	value, ok := metadataBoolValue(metadata, key)
	return ok && value == expected
}

func metadataUint64(metadata map[string]any, key string) uint64 {
	switch value := metadata[key].(type) {
	case uint64:
		return value
	case float64:
		if value > 0 && value == float64(uint64(value)) {
			return uint64(value)
		}
	case json.Number:
		parsed, errParse := value.Int64()
		if errParse == nil && parsed > 0 {
			return uint64(parsed)
		}
	}
	return 0
}
