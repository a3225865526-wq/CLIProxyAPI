package management

import (
	"net/http"

	"github.com/gin-gonic/gin"
	coreauth "github.com/router-for-me/CLIProxyAPI/v8/sdk/cliproxy/auth"
)

func (h *Handler) GetPoolIsolation(c *gin.Context) {
	role := ""
	if h.authManager != nil {
		role = h.authManager.PoolRole()
	}
	c.JSON(http.StatusOK, gin.H{"role": role, "guard_version": coreauth.PoolGuardVersion, "deployment_verified": false})
}
