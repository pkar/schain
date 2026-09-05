package main

import "testing"

func TestTTLRejectsOverflow(t *testing.T) {
	for _, s := range []string{"9223372036854775807", "35791395", "596524h"} {
		if ttl, err := parseTTL(s); err == nil {
			t.Errorf("accepted %q as %d seconds", s, ttl)
		}
	}
	for _, s := range []string{"30m", "8h", "1h30m", "90s", "1"} {
		if ttl, err := parseTTL(s); err != nil || ttl <= 0 {
			t.Errorf("rejected valid %q: %d %v", s, ttl, err)
		}
	}
}
