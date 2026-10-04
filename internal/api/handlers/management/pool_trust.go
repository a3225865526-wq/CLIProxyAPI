package management

import (
	"encoding/json"
	"io"
	"net/http"

	"github.com/gin-gonic/gin"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func (h *Handler) GetPoolTrust(c *gin.Context) {
	if h.authManager == nil {
		c.AbortWithStatus(http.StatusServiceUnavailable)
		return
	}
	revision, identities, err := h.authManager.PoolTrustSnapshot()
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "pool_admission_required"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"revision": revision, "identities": identities, "in_flight": h.authManager.PoolInFlightSnapshot()})
}

func decodePoolCommand(c *gin.Context, command any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(c.Writer, c.Request.Body, 64*1024))
	decoder.DisallowUnknownFields()
	var extra any
	if decoder.Decode(command) != nil || decoder.Decode(&extra) != io.EOF {
		c.JSON(http.StatusBadRequest, gin.H{"error": "invalid_pool_command"})
		return false
	}
	return true
}

func (h *Handler) PromotePoolTrust(c *gin.Context) {
	var command coreauth.PoolPromotion
	if !decodePoolCommand(c, &command) {
		return
	}
	if h.authManager == nil {
		c.AbortWithStatus(http.StatusServiceUnavailable)
		return
	}
	if err := h.authManager.PromotePoolIdentities(c.Request.Context(), command); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "pool_promotion_rejected"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "trusted"})
}

func (h *Handler) RevokePoolTrust(c *gin.Context) {
	var command coreauth.PoolRevocation
	if !decodePoolCommand(c, &command) {
		return
	}
	if h.authManager == nil {
		c.AbortWithStatus(http.StatusServiceUnavailable)
		return
	}
	if err := h.authManager.RevokePoolIdentity(c.Request.Context(), command); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "pool_revocation_rejected"})
		return
	}
	// Remote termination is not implied by this local cancellation boundary.
	c.JSON(http.StatusOK, gin.H{"status": "revoked", "local_cancellation_requested": true})
}
