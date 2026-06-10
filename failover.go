package castle

// failoverResponse builds the synthetic response returned by Risk and Filter
// when the API is unavailable (or tracking is disabled).
func failoverResponse(userID string, strategy FailoverStrategy, reason string) Params {
	action := string(strategy)
	return Params{
		"policy":          Params{"action": action},
		"action":          action,
		"user_id":         userID,
		"failover":        true,
		"failover_reason": reason,
	}
}

// failoverUserID resolves the user identifier echoed back in a failover
// response: user.id, then matching_user_id, otherwise empty.
func failoverUserID(payload Params) string {
	if user, ok := payload["user"].(map[string]interface{}); ok {
		if id, ok := user["id"].(string); ok {
			return id
		}
	}
	if id, ok := payload["matching_user_id"].(string); ok {
		return id
	}
	return ""
}
