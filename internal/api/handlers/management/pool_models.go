package management

import (
	"net/http"

	"github.com/gin-gonic/gin"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

// GetPoolModels reports the capability ledger next to the trust snapshot, so an
// operator can see which account×model grants are bound to which generation.
func (h *Handler) GetPoolModels(c *gin.Context) {
	if h.authManager == nil {
		c.AbortWithStatus(http.StatusServiceUnavailable)
		return
	}
	revision, capabilities, err := h.authManager.PoolModelSnapshot()
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "pool_admission_required"})
		return
	}
	trustRevision, identities, trustErr := h.authManager.PoolTrustSnapshot()
	if trustErr != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "pool_admission_required"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"revision": revision, "trust_revision": trustRevision, "capabilities": capabilities, "identities": identities, "in_flight": h.authManager.PoolInFlightSnapshot()})
}

func (h *Handler) GrantPoolModel(c *gin.Context) {
	var command coreauth.PoolModelGrant
	if !decodePoolCommand(c, &command) {
		return
	}
	if h.authManager == nil {
		c.AbortWithStatus(http.StatusServiceUnavailable)
		return
	}
	if err := h.authManager.GrantPoolModelCapability(c.Request.Context(), command); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "pool_model_grant_rejected"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "granted"})
}

func (h *Handler) RevokePoolModel(c *gin.Context) {
	var command coreauth.PoolModelRevoke
	if !decodePoolCommand(c, &command) {
		return
	}
	if h.authManager == nil {
		c.AbortWithStatus(http.StatusServiceUnavailable)
		return
	}
	if err := h.authManager.RevokePoolModelCapability(c.Request.Context(), command); err != nil {
		c.JSON(http.StatusConflict, gin.H{"error": "pool_model_revocation_rejected"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": "revoked", "local_cancellation_requested": true})
}
