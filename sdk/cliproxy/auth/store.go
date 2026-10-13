package auth

import "context"

// Store abstracts persistence of Auth state across restarts.
type Store interface {
	// List returns all auth records stored in the backend.
	List(ctx context.Context) ([]*Auth, error)
	// Save persists the provided auth record, replacing any existing one with same ID.
	Save(ctx context.Context, auth *Auth) (string, error)
	// Delete removes the auth record identified by id.
	Delete(ctx context.Context, id string) error
}

// ManagementDisableStore must confirm both operator isolation fields and the
// file/directory durability barrier. Ordinary Save success is not this proof.
type ManagementDisableStore interface {
	ConfirmManagementDisable(context.Context, *Auth) error
}

type ManagementRecoveryState string

const (
	ManagementRecoveryPrepared  ManagementRecoveryState = "PREPARED"
	ManagementRecoveryCommitted ManagementRecoveryState = "COMMITTED"
)

type ManagementRecoveryOperation struct {
	OpID             string                  `json:"op_id"`
	AuthID           string                  `json:"auth_id"`
	CredentialDigest string                  `json:"credential_digest"`
	Generation       uint64                  `json:"generation"`
	Revision         uint64                  `json:"revision"`
	State            ManagementRecoveryState `json:"state"`
	TargetDisabled   bool                    `json:"target_disabled"`
}

type ManagementRecoveryStore interface {
	PrepareManagementRecovery(context.Context, *Auth, ManagementRecoveryOperation) error
	CommitManagementRecovery(context.Context, *Auth, ManagementRecoveryOperation) (ManagementRecoveryState, error)
	VerifyManagementRecovery(context.Context, *Auth, ManagementRecoveryOperation) (ManagementRecoveryState, error)
}

type ManagementRecoveryOutcomeError struct {
	Status string
	OpID   string
	Err    error
}

func (e *ManagementRecoveryOutcomeError) Error() string {
	if e == nil {
		return "management recovery"
	}
	message := "management recovery " + e.Status
	if e.OpID != "" {
		message += " op_id=" + e.OpID
	}
	if e.Err != nil {
		message += ": " + e.Err.Error()
	}
	return message
}

func (e *ManagementRecoveryOutcomeError) Unwrap() error {
	if e == nil {
		return nil
	}
	return e.Err
}
