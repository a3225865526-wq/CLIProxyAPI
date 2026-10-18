package management

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/gin-gonic/gin"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

const maxPoolImportBytes = 256 * 1024

// ImportCredentialAtomic installs exactly one top-level Codex OAuth file.
// Validation happens before mutation; a registration failure removes the
// staged file, and no response carries token material.
func (h *Handler) ImportCredentialAtomic(c *gin.Context) {
	if h == nil || h.authManager == nil || h.cfg == nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "core auth manager unavailable"})
		return
	}
	var command struct {
		Name    string `json:"name"`
		Content string `json:"content"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(c.Writer, c.Request.Body, 2*maxPoolImportBytes))
	decoder.DisallowUnknownFields()
	var trailing any
	if decoder.Decode(&command) != nil || decoder.Decode(&trailing) != io.EOF {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid import"})
		return
	}
	name := filepath.Base(strings.TrimSpace(command.Name))
	if name == "." || name == "" || !strings.HasSuffix(strings.ToLower(name), ".json") || strings.ContainsAny(name, "/\\\x00") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid file name"})
		return
	}
	raw, err := base64.StdEncoding.DecodeString(command.Content)
	if err != nil || len(raw) == 0 || len(raw) > maxPoolImportBytes {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid import"})
		return
	}
	metadata := map[string]any{}
	if json.Unmarshal(raw, &metadata) != nil || metadata == nil || metadata["type"] != "codex" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported credential"})
		return
	}
	for _, key := range []string{"access_token", "refresh_token"} {
		value, ok := metadata[key].(string)
		if !ok || strings.TrimSpace(value) == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "incomplete credential"})
			return
		}
	}
	authDir, err := filepath.Abs(h.cfg.AuthDir)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "auth store unavailable"})
		return
	}
	stat, err := os.Stat(authDir)
	if err != nil || !stat.IsDir() {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": "auth store unavailable"})
		return
	}
	target := filepath.Join(authDir, name)
	auth, err := h.buildAuthFromFileData(target, raw)
	if err != nil || auth == nil || auth.Provider != "codex" || auth.AuthKind() != coreauth.AuthKindOAuth {
		c.JSON(http.StatusBadRequest, gin.H{"error": "unsupported credential"})
		return
	}
	authID := h.authIDForPath(target)
	if authID == "" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "import failed"})
		return
	}
	auth.ID = authID
	auth.FileName = name
	if existing, ok := h.authManager.GetByID(authID); ok && existing != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "credential exists"})
		return
	}

	temp, err := os.CreateTemp(authDir, ".pool-import-*.tmp")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "import failed"})
		return
	}
	tempName := temp.Name()
	cleanupTemp := func() {
		_ = temp.Close()
		_ = os.Remove(tempName)
	}
	if err := temp.Chmod(0o600); err != nil {
		cleanupTemp()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "import failed"})
		return
	}
	if _, err := io.Copy(temp, bytes.NewReader(raw)); err != nil {
		cleanupTemp()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "import failed"})
		return
	}
	if err := temp.Sync(); err != nil {
		cleanupTemp()
		c.JSON(http.StatusInternalServerError, gin.H{"error": "import failed"})
		return
	}
	if err := temp.Close(); err != nil {
		_ = os.Remove(tempName)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "import failed"})
		return
	}
	if err := os.Rename(tempName, target); err != nil {
		_ = os.Remove(tempName)
		c.JSON(http.StatusConflict, gin.H{"error": "credential exists"})
		return
	}
	committed := false
	defer func() {
		if !committed {
			_ = os.Remove(target)
			h.removeAuthsForPath(context.Background(), target, authID)
		}
	}()
	auth.Attributes["path"] = target
	auth.Attributes["source"] = target
	auth.Metadata = metadata
	coreauth.NormalizeCredentialMetadata(auth.Metadata)
	// Pool imports are quarantined at rest: the file becomes schedulable only
	// after the operator separately grants and promotes the exact identity.
	// This mirrors saveTokenRecord and keeps a crashed import fail-closed.
	auth.Disabled = true
	auth.Status = coreauth.StatusDisabled
	auth.Metadata["disabled"] = true
	auth.Metadata[coreauth.ManagementDisabledKey] = true
	// Persist the quarantine fence in the credential file itself. Registering
	// only the in-memory record would allow a restart to reintroduce unmarked
	// raw bytes from the target path.
	storedRaw, errMarshal := json.Marshal(auth.Metadata)
	if errMarshal != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "import failed"})
		return
	}
	if errWrite := replaceImportFileAtomic(target, storedRaw); errWrite != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "import failed"})
		return
	}
	if err := h.upsertAuthRecord(c.Request.Context(), auth); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "import failed"})
		return
	}
	if h.postAuthPersistHook != nil {
		if err := h.postAuthPersistHook(c.Request.Context(), auth); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "import failed"})
			return
		}
	}
	digest := coreauth.PoolCredentialDigest(auth)
	if digest == "" {
		_ = os.Remove(target)
		h.removeAuthsForPath(context.Background(), target, authID)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "import failed"})
		return
	}
	// Only after registration and the canonical digest both succeed is the
	// import committed. A later client disconnect cannot delete it.
	committed = true
	c.JSON(http.StatusOK, gin.H{
		"credential_ref":    filepath.Base(target),
		"credential_digest": digest,
		"provider":          "codex",
	})
}

// deleteImportedFile is used both by local tests and the compensating path.
func deleteImportedFile(path string) error {
	if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}

func replaceImportFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	temp, err := os.CreateTemp(dir, ".pool-import-rewrite-*.tmp")
	if err != nil {
		return err
	}
	tempName := temp.Name()
	cleanup := func() {
		_ = temp.Close()
		_ = os.Remove(tempName)
	}
	if errChmod := temp.Chmod(0o600); errChmod != nil {
		cleanup()
		return errChmod
	}
	if _, errWrite := temp.Write(data); errWrite != nil {
		cleanup()
		return errWrite
	}
	if errSync := temp.Sync(); errSync != nil {
		cleanup()
		return errSync
	}
	if errClose := temp.Close(); errClose != nil {
		_ = os.Remove(tempName)
		return errClose
	}
	if errRename := os.Rename(tempName, path); errRename != nil {
		_ = os.Remove(tempName)
		return errRename
	}
	return nil
}
