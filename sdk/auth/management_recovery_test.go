package auth

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func TestFileStoreManagementRecoveryWALCommitAndReload(t *testing.T) {
	if !managementPersistenceQualified() {
		t.Skip("filesystem durability contract is not qualified on this platform")
	}

	dir := t.TempDir()
	store := NewFileTokenStore()
	store.SetBaseDir(dir)
	auth := &coreauth.Auth{
		ID:       "recovery.json",
		FileName: "recovery.json",
		Provider: "codex",
		Status:   coreauth.StatusDisabled,
		Disabled: true,
		Attributes: map[string]string{
			coreauth.AttributeAuthKind: coreauth.AuthKindOAuth,
		},
		Metadata: map[string]any{
			"type":                         "codex",
			"access_token":                 "synthetic-unused",
			"account_id":                   "recovery-account",
			"email":                        "recovery@test.invalid",
			coreauth.ManagementDisabledKey: true,
		},
	}
	ctx := coreauth.WithAuthCreationIntent(context.Background())
	if _, errSave := store.Save(ctx, auth); errSave != nil {
		t.Fatal(errSave)
	}

	op := coreauth.ManagementRecoveryOperation{
		OpID:             "recovery-operation-1",
		AuthID:           auth.ID,
		CredentialDigest: coreauth.PoolCredentialDigest(auth),
		Generation:       3,
		Revision:         7,
		State:            coreauth.ManagementRecoveryPrepared,
	}
	if errPrepare := store.PrepareManagementRecovery(ctx, auth, op); errPrepare != nil {
		t.Fatal(errPrepare)
	}

	candidate := auth.Clone()
	candidate.Disabled = false
	candidate.Status = coreauth.StatusActive
	candidate.Metadata["disabled"] = false
	candidate.Metadata[coreauth.ManagementDisabledKey] = false
	candidate.Metadata[coreauth.RecoveryOpIDKey] = op.OpID
	candidate.Metadata[coreauth.RecoveryGenerationKey] = op.Generation
	candidate.Metadata[coreauth.RecoveryRevisionKey] = op.Revision
	candidate.Metadata[coreauth.RecoveryStateKey] = string(coreauth.ManagementRecoveryPrepared)
	if _, errSave := store.Save(coreauth.WithManagementRecoveryDurability(ctx), candidate); errSave != nil {
		t.Fatal(errSave)
	}

	state, errCommit := store.CommitManagementRecovery(ctx, candidate, op)
	if errCommit != nil || state != coreauth.ManagementRecoveryCommitted {
		t.Fatalf("commit state=%s err=%v", state, errCommit)
	}
	state, errVerify := store.VerifyManagementRecovery(ctx, candidate, op)
	if errVerify != nil || state != coreauth.ManagementRecoveryCommitted {
		t.Fatalf("verify state=%s err=%v", state, errVerify)
	}

	walData, errRead := os.ReadFile(filepath.Join(dir, "recovery.json.management-recovery.wal"))
	if errRead != nil {
		t.Fatal(errRead)
	}
	var record managementRecoveryRecord
	if errDecode := json.Unmarshal(walData, &record); errDecode != nil || !record.valid() || record.State != coreauth.ManagementRecoveryCommitted {
		t.Fatalf("invalid committed WAL: %s %v", walData, errDecode)
	}

	loaded, errList := store.List(context.Background())
	if errList != nil || len(loaded) != 1 {
		t.Fatalf("reload failed: %v %+v", errList, loaded)
	}
	if loaded[0].Disabled || loaded[0].Metadata[coreauth.RecoveryStateKey] != string(coreauth.ManagementRecoveryCommitted) || loaded[0].Generation != op.Generation {
		t.Fatalf("reload did not admit committed recovery: %+v", loaded[0])
	}
	if errRemove := os.Remove(filepath.Join(dir, "recovery.json.management-recovery.wal")); errRemove != nil {
		t.Fatal(errRemove)
	}
	loaded, errList = store.List(context.Background())
	if errList != nil || len(loaded) != 1 || !loaded[0].Disabled {
		t.Fatalf("missing WAL bypassed recovery isolation: %v %+v", errList, loaded)
	}
}
