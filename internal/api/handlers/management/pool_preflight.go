package management

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	cliproxyexecutor "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/executor"
)

// PoolRequestPreflight accepts request shape only. It never dispatches or
// reserves an account and returns no credential identifiers or material.
func (h *Handler) PoolRequestPreflight(c *gin.Context) {
	if h.authManager == nil {
		c.AbortWithStatus(http.StatusServiceUnavailable)
		return
	}
	c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, 1<<20)
	var command struct {
		Model   string          `json:"model"`
		AuthID  string          `json:"auth_id"`
		Stream  bool            `json:"stream"`
		Request json.RawMessage `json:"request"`
	}
	decoder := json.NewDecoder(c.Request.Body)
	decoder.DisallowUnknownFields()
	var trailing any
	if decoder.Decode(&command) != nil || decoder.Decode(&trailing) != io.EOF || command.Model == "" || len(command.Request) == 0 {
		c.JSON(http.StatusBadRequest, gin.H{"error": "preflight_request_invalid"})
		return
	}
	var schema map[string]any
	if json.Unmarshal(command.Request, &schema) != nil || schema == nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "preflight_request_invalid"})
		return
	}
	if model, exists := schema["model"]; exists && model != command.Model {
		c.JSON(http.StatusBadRequest, gin.H{"error": "preflight_request_invalid"})
		return
	}
	if stream, exists := schema["stream"]; exists && stream != nil && stream != command.Stream {
		c.JSON(http.StatusBadRequest, gin.H{"error": "preflight_request_invalid"})
		return
	}
	result, err := h.authManager.PoolRequestPreflight(c.Request.Context(), command.Model, cliproxyexecutor.Options{OriginalRequest: command.Request, Stream: command.Stream, Metadata: map[string]any{cliproxyexecutor.PinnedAuthMetadataKey: command.AuthID}})
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "pool_admission_required"})
		return
	}
	c.JSON(http.StatusOK, result)
}
