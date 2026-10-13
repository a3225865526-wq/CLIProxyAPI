package auth

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
)

func TestPoolTerminalTransportHandoffReleasesAfterDrain(t *testing.T) {
	for _, order := range []string{"transport_first", "drain_first", "concurrent", "revoke_close"} {
		t.Run(order, func(t *testing.T) {
			for iteration := 0; iteration < 50; iteration++ {
				ctx, cancel := context.WithCancelCause(context.Background())
				g := &poolGuard{leases: make(map[uint64]*poolLease), counts: map[string]int{"synthetic": 1}}
				m := &Manager{poolGuard: g}
				var closes atomic.Int32
				l := &poolLease{PoolInFlight: PoolInFlight{RequestID: 1, AuthID: "synthetic"}, manager: m, ctx: ctx, cancel: cancel, persistent: true, retained: true, closeFn: func() error { closes.Add(1); return nil }}
				g.leases[1] = l
				switch order {
				case "transport_first":
					l.TransportClosed("upstream_disconnected")
					if ctx.Err() != nil || closes.Load() != 0 {
						t.Fatal("terminal handoff canceled undrained output")
					}
					l.End("stream_end")
				case "drain_first":
					l.End("stream_end")
					if ctx.Err() != nil || len(g.leases) != 1 || g.counts["synthetic"] != 0 {
						t.Fatal("live persistent socket must retain revocation entry after turn drain")
					}
					l.TransportClosed("upstream_disconnected")
				case "concurrent", "revoke_close":
					var wg sync.WaitGroup
					wg.Add(3)
					go func() { defer wg.Done(); l.TransportClosed("upstream_disconnected") }()
					go func() { defer wg.Done(); l.End("stream_end") }()
					go func() {
						defer wg.Done()
						if order == "revoke_close" {
							cancel(ErrAccountRevoked)
							l.End("revoked")
						} else {
							l.TransportClosed("connection_closed")
						}
					}()
					wg.Wait()
				}
				l.End("session_closed")
				if len(g.leases) != 0 || g.counts["synthetic"] != 0 || closes.Load() != 1 || ctx.Err() == nil {
					t.Fatalf("final state: leases=%d concurrency=%d closes=%d canceled=%v", len(g.leases), g.counts["synthetic"], closes.Load(), ctx.Err())
				}
			}
		})
	}
}
