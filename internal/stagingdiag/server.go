package stagingdiag

import (
	"crypto/sha256"
	"crypto/subtle"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"os"
	"time"
)

const Path = "/stage74/runtime"

var grantPath = "/run/clearapi-stage74/operator.json"

type grant struct {
	Purpose string `json:"purpose"`
	Key     string `json:"key"`
	Expires int64  `json:"expires"`
}

func loadGrant(path string) (grant, error) {
	var g grant
	st, err := os.Lstat(path)
	if err != nil {
		return g, err
	}
	if !st.Mode().IsRegular() || st.Mode().Perm() != 0600 || st.Size() > 1024 {
		return g, errors.New("invalid staging diagnostic authorization")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return g, err
	}
	err = json.Unmarshal(data, &g)
	if err != nil {
		return grant{}, errors.New("invalid staging diagnostic authorization")
	}
	key, err := hex.DecodeString(g.Key)
	remaining := time.Until(time.Unix(g.Expires, 0))
	if err != nil || len(key) != 32 || g.Purpose != "local-staging" || remaining <= 0 || remaining > 15*time.Minute {
		return grant{}, errors.New("invalid staging diagnostic authorization")
	}
	return g, nil
}

// Handler has no business mutation or provider transport capabilities.
func Handler(key string, expires time.Time, read func() (any, error), now func() time.Time) http.Handler {
	digest := sha256.Sum256([]byte("Bearer " + key))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "no-store")
		peer, _, err := net.SplitHostPort(r.RemoteAddr)
		if err != nil || peer != "127.0.0.1" || r.Header.Get("Origin") != "" {
			http.Error(w, "forbidden", http.StatusForbidden)
			return
		}
		if r.Method != http.MethodGet || r.URL.Path != Path || r.URL.RawQuery != "" {
			http.NotFound(w, r)
			return
		}
		supplied := sha256.Sum256([]byte(r.Header.Get("Authorization")))
		if subtle.ConstantTimeCompare(digest[:], supplied[:]) != 1 {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		if !now().Before(expires) {
			http.Error(w, "expired", http.StatusGone)
			return
		}
		value, err := read()
		if err != nil {
			http.Error(w, "runtime unavailable", http.StatusServiceUnavailable)
			return
		}
		data, err := json.Marshal(value)
		if err != nil {
			http.Error(w, "runtime unavailable", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(data)
	})
}
