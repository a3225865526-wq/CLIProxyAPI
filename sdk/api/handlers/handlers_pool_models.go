package handlers

// FilterPoolModelCatalog applies current admission to exposed catalog metadata.
// A cached registry entry alone cannot advertise an expired or revoked pool model.
func (h *BaseAPIHandler) FilterPoolModelCatalog(models []map[string]any) []map[string]any {
	if h == nil || h.AuthManager == nil || h.AuthManager.PoolRole() != "service" {
		return models
	}
	allowed := make([]map[string]any, 0, len(models))
	for _, model := range models {
		id, _ := model["id"].(string)
		if len(h.AuthManager.PoolModelProviders(id)) != 0 {
			allowed = append(allowed, model)
		}
	}
	return allowed
}
