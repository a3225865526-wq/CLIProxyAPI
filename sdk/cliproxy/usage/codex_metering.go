package usage

import (
	"context"
	"encoding/json"
)

type codexObserverKey struct{}

func WithCodexMeteringObserver(ctx context.Context, observe func(*CodexMetering)) context.Context {
	return context.WithValue(ctx, codexObserverKey{}, observe)
}
func ObserveCodexMetering(ctx context.Context, m *CodexMetering) {
	if m == nil || !m.Final || m.Status != "exact" {
		return
	}
	if observe, ok := ctx.Value(codexObserverKey{}).(func(*CodexMetering)); ok {
		observe(m)
	}
}

// CodexMetering preserves upstream field presence. Cache and reasoning are
// subsets of input and output, never additional tokens.
type CodexMetering struct {
	CacheWrite   *int64 `json:"cache_write_tokens,omitempty"`
	Final        bool   `json:"final"`
	Status       string `json:"status"`
	Source       string `json:"source"`
	Input        *int64 `json:"input_tokens"`
	Cached       *int64 `json:"cached_input_tokens"`
	Output       *int64 `json:"output_tokens"`
	Reasoning    *int64 `json:"reasoning_tokens"`
	Total        *int64 `json:"total_tokens"`
	TotalDerived bool   `json:"total_derived"`
	Reason       string `json:"reason,omitempty"`
	AttemptID    string `json:"attempt_id,omitempty"`
	AccountRef   string `json:"account_ref,omitempty"`
	Model        string `json:"model,omitempty"`
	ResponseID   string `json:"response_id,omitempty"`
}

// ParseCodexMetering accepts only JSON integers in the bounded meter domain.
// It never repairs contradictory totals or invents missing detail counters.
func ParseCodexMetering(raw []byte) *CodexMetering {
	m := &CodexMetering{Status: "unavailable", Source: "codex_upstream", Reason: "missing_usage"}
	var fields map[string]json.RawMessage
	if len(raw) == 0 || string(raw) == "null" {
		return m
	}
	if json.Unmarshal(raw, &fields) != nil || fields == nil {
		m.Reason = "malformed_usage"
		return m
	}
	invalid := false
	read := func(name, alias string) *int64 {
		var result *int64
		for _, key := range []string{name, alias} {
			if key == "" {
				continue
			}
			raw, exists := fields[key]
			if !exists {
				continue
			}
			var n int64
			if string(raw) == "null" || json.Unmarshal(raw, &n) != nil || n < 0 || n > 1_000_000_000_000 {
				invalid = true
				continue
			}
			if result != nil && *result != n {
				invalid = true
			}
			value := n
			result = &value
		}
		return result
	}
	m.Input = read("input_tokens", "prompt_tokens")
	m.Output = read("output_tokens", "completion_tokens")
	m.Total = read("total_tokens", "")
	for _, item := range []struct {
		names []string
		key   string
		dst   **int64
	}{
		{[]string{"input_tokens_details", "prompt_tokens_details"}, "cached_tokens", &m.Cached},
		{[]string{"output_tokens_details", "completion_tokens_details"}, "reasoning_tokens", &m.Reasoning},
		{[]string{"input_tokens_details", "prompt_tokens_details"}, "cache_write_tokens", &m.CacheWrite},
	} {
		for _, name := range item.names {
			raw, exists := fields[name]
			if !exists {
				continue
			}
			var details map[string]json.RawMessage
			if json.Unmarshal(raw, &details) != nil || details == nil {
				invalid = true
				continue
			}
			value, exists := details[item.key]
			if !exists {
				continue
			}
			var n int64
			if string(value) == "null" || json.Unmarshal(value, &n) != nil || n < 0 || n > 1_000_000_000_000 {
				invalid = true
				continue
			}
			if *item.dst != nil && **item.dst != n {
				invalid = true
			}
			v := n
			*item.dst = &v
		}
	}
	if invalid {
		m.Reason = "malformed_usage"
		return m
	}
	m.Validate()
	return m
}

// Validate also guards decoded proxy envelopes before they reach accounting.
func (m *CodexMetering) Validate() bool {
	for _, n := range []*int64{m.Input, m.Cached, m.Output, m.Reasoning, m.Total, m.CacheWrite} {
		if n != nil && (*n < 0 || *n > 1_000_000_000_000) {
			m.Status, m.Reason = "unavailable", "invalid_usage"
			return false
		}
	}
	if m.Input == nil || m.Output == nil || m.Cached == nil || m.Reasoning == nil {
		m.Status, m.Reason = "unavailable", "partial_usage"
		return false
	}
	if *m.Cached > *m.Input || *m.Reasoning > *m.Output {
		m.Status, m.Reason = "unavailable", "inconsistent_details"
		return false
	}
	if m.CacheWrite != nil && *m.Cached+*m.CacheWrite > *m.Input {
		m.Status, m.Reason = "unavailable", "inconsistent_details"
		return false
	}
	sum := *m.Input + *m.Output // Individually bounded above; cannot overflow.
	if m.Total == nil {
		m.Total = &sum
		m.TotalDerived = true
	}
	if *m.Total != sum {
		m.Status, m.Reason = "unavailable", "inconsistent_total"
		return false
	}
	m.Status, m.Reason = "exact", ""
	return true
}
