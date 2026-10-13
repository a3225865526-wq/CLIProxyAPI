package auth

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"

	codexauth "github.com/router-for-me/CLIProxyAPI/v8/internal/auth/codex"
)

// CredentialSecurityIdentityVersion is the schema version of the canonical
// credential security identity digest. Version 1 (implicit, unversioned) hashed
// the auth ID, file name, every Attribute, and every Metadata entry, so the
// filestore startup loader and the watcher synthesizer derived different
// digests for the same credential (PG-29): trust did not survive a restart and
// a normal token refresh burned it. Version 2 hashes an explicit whitelist of
// stable identity material only, with a fixed serialization.
const CredentialSecurityIdentityVersion = 2

// credentialSecurityIdentity is the complete whitelist hashed into the
// canonical credential digest. A struct (never a map) fixes field order and
// encoding, so identical identity material always serializes to identical
// bytes.
//
// accountSubject is the stable provider-side account identifier. Deliberately
// excluded: rotating token material (access token, refresh token, id_token
// bytes, expiry, refresh timestamps), derived metadata (plan type, excluded
// models, aliases), deployment metadata (auth ID, file name, absolute path,
// attributes), and runtime state. A normal access-token refresh must not
// change the identity; replacing the credential with a different provider
// account always must.
type credentialSecurityIdentity struct {
	SchemaVersion  int    `json:"schema_version"`
	Provider       string `json:"provider"`
	CredentialKind string `json:"credential_kind"`
	AccountSubject string `json:"account_subject"`
}

// PoolCredentialDigest returns the canonical credential security identity
// digest. Every security consumer (trust promotion and revocation, capability
// binding, operator grants, dispatch leases, pending identity exposure) must
// use exactly this function; no call site may re-derive a credential digest.
//
// The result is stable across loader pipelines (filestore startup load, watcher
// synthesis, runtime enrichment), container mount paths, and token refreshes.
// An empty result means the credential carries no stable identity material;
// such a credential can never be promoted (fail closed). The digest never
// contains or exposes credential contents.
func PoolCredentialDigest(auth *Auth) string {
	identity, ok := canonicalCredentialIdentity(auth)
	if !ok {
		return ""
	}
	payload, err := json.Marshal(identity)
	if err != nil {
		return ""
	}
	sum := sha256.Sum256(payload)
	return hex.EncodeToString(sum[:])
}

// canonicalCredentialIdentity extracts the whitelisted identity material.
func canonicalCredentialIdentity(auth *Auth) (credentialSecurityIdentity, bool) {
	if auth == nil {
		return credentialSecurityIdentity{}, false
	}
	kind := auth.AuthKind()
	if kind != AuthKindOAuth && kind != AuthKindAPIKey {
		return credentialSecurityIdentity{}, false
	}
	provider := strings.ToLower(strings.TrimSpace(auth.Provider))
	if provider == "" {
		return credentialSecurityIdentity{}, false
	}
	subject := ""
	if kind == AuthKindAPIKey {
		subject = stableAPIKeySubject(auth)
	} else {
		subject = stableOAuthAccountSubject(auth)
	}
	if subject == "" {
		return credentialSecurityIdentity{}, false
	}
	return credentialSecurityIdentity{
		SchemaVersion:  CredentialSecurityIdentityVersion,
		Provider:       provider,
		CredentialKind: kind,
		AccountSubject: subject,
	}, true
}

// stableOAuthAccountSubject derives the stable account subject from metadata
// only: every loader pipeline starts from the same raw credential JSON, so
// pipeline-specific Attributes can never influence the outcome. The chain
// prefers the provider account identifier and OAuth identity claims over the
// low-entropy email fallback, and never falls back to rotating token material.
func stableOAuthAccountSubject(auth *Auth) string {
	if auth == nil {
		return ""
	}
	if subject := authMetadataString(auth, "account_id"); subject != "" {
		return subject
	}
	idToken := authMetadataString(auth, "id_token")
	if idToken == "" {
		idToken = authMetadataString(auth, "idToken")
	}
	if idToken != "" {
		if claims, err := codexauth.ParseJWTToken(idToken); err == nil && claims != nil {
			if subject := strings.TrimSpace(claims.CodexAuthInfo.ChatgptAccountID); subject != "" {
				return subject
			}
			if subject := strings.TrimSpace(claims.Sub); subject != "" {
				return subject
			}
		}
	}
	if subject := authMetadataString(auth, "sub"); subject != "" {
		return subject
	}
	if subject := authMetadataString(auth, "user_id"); subject != "" {
		return subject
	}
	if subject := authMetadataString(auth, "email"); subject != "" {
		return strings.ToLower(subject)
	}
	return ""
}

// stableAPIKeySubject hashes the API key material so the digest input never
// carries the secret itself, while a rotated key still changes the identity.
func stableAPIKeySubject(auth *Auth) string {
	subject := authAttribute(auth, AttributeAPIKey)
	if subject == "" {
		subject = authMetadataString(auth, AttributeAPIKey)
	}
	if subject == "" {
		return ""
	}
	sum := sha256.Sum256([]byte(subject))
	return hex.EncodeToString(sum[:])
}
