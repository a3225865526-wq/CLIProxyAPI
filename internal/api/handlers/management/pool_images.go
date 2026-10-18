package management

import (
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
)

// GetPoolImagesExecution reports the durable outcome of one controlled image
// attempt. It never returns image bytes and never mutates execution state, so
// a Gateway that lost a receipt can resolve its own UNKNOWN safely.
func (h *Handler) GetPoolImagesExecution(c *gin.Context) {
	if h.authManager == nil {
		c.AbortWithStatus(http.StatusServiceUnavailable)
		return
	}
	record, err := h.authManager.QueryImagesExecution(c.Param("request"), c.Param("attempt"))
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "images_execution_unavailable"})
		return
	}
	c.JSON(http.StatusOK, record)
}

// GetPoolImagesResult returns the persisted image payload after verifying its
// metadata and digest. A mismatch is reported as unavailable, never repaired.
func (h *Handler) GetPoolImagesResult(c *gin.Context) {
	if h.authManager == nil {
		c.AbortWithStatus(http.StatusServiceUnavailable)
		return
	}
	payload, meta, err := h.authManager.LoadImagesResult(c.Param("request"), c.Param("attempt"))
	if err != nil {
		c.JSON(http.StatusForbidden, gin.H{"error": "images_result_unavailable"})
		return
	}
	c.Header("Content-Type", "application/json")
	c.Header("X-ClearAPI-Images-Result-SHA256", meta.ResultSHA256)
	c.Header("X-ClearAPI-Images-Billable-Count", strconv.Itoa(meta.BillableImageCount))
	c.Data(http.StatusOK, "application/json", payload)
}
