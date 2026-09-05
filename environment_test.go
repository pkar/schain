package main

import (
	"strings"
	"testing"
)

func TestEnvironmentRejectsMalformedEntries(t *testing.T) {
	t.Setenv("SCHAIN_ACTIVE", "")
	for _, secrets := range []map[string]string{
		{"SCHAIN_KEYS=bad": "value"}, {"": "value"}, {"bad\x00key": "value"}, {"KEY": "bad\x00value"},
	} {
		if _, err := secretEnviron(secrets, nil, ""); err == nil {
			t.Error("malformed environment accepted")
		}
	}
	t.Setenv("SCHAIN_ACTIVE", "/test/.schain")
	for _, raw := range []string{`[null]`, `[""]`, `["A=B"]`, `["A\u0000B"]`} {
		t.Setenv("SCHAIN_KEYS", raw)
		if _, err := secretEnviron(nil, nil, ""); err == nil {
			t.Errorf("malformed inventory accepted: %s", raw)
		}
	}
}

func TestEnvironmentInventoryFailsClosed(t *testing.T) {
	t.Setenv("SCHAIN_ACTIVE", "/test/.schain")
	for _, raw := range []string{"", "null", "{}", "broken", `[1]`} {
		t.Setenv("SCHAIN_KEYS", raw)
		if _, err := secretEnviron(nil, nil, ""); err == nil {
			t.Errorf("accepted invalid inventory %q", raw)
		}
	}
}

func TestEnvironmentInventoryCannotBeShadowed(t *testing.T) {
	t.Setenv("SCHAIN_ACTIVE", "")
	env, err := secretEnviron(map[string]string{"SCHAIN_ACTIVE": "bad", "SCHAIN_KEYS": "bad", "SCHAIN_SHELL": "bad"}, []string{"/test/.schain"}, "/bin/bash")
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]int{}
	for _, kv := range env {
		k, val, _ := strings.Cut(kv, "=")
		seen[k]++
		if strings.HasPrefix(k, "SCHAIN_") && val == "bad" {
			t.Errorf("marker shadowed: %s", k)
		}
	}
	for _, k := range []string{"SCHAIN_ACTIVE", "SCHAIN_KEYS", "SCHAIN_SHELL"} {
		if seen[k] != 1 {
			t.Errorf("%s count = %d", k, seen[k])
		}
	}
	t.Setenv("SCHAIN_ACTIVE", "/test/.schain")
	t.Setenv("SCHAIN_KEYS", "[]")
	if _, err := secretEnviron(nil, nil, ""); err != nil {
		t.Fatal(err)
	}
}

func TestReloadDropsPreviouslyInjectedKeys(t *testing.T) {
	t.Setenv("SCHAIN_ACTIVE", "/test/.schain")
	t.Setenv("SCHAIN_KEYS", `["REMOVED","KEPT"]`)
	t.Setenv("REMOVED", "synthetic-old-value")
	t.Setenv("KEPT", "old")
	t.Setenv("UNRELATED", "keep")
	env, err := secretEnviron(map[string]string{"KEPT": "new"}, []string{"/test/.schain"}, "/bin/bash")
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]string{}
	for _, kv := range env {
		k, v, _ := strings.Cut(kv, "=")
		got[k] = v
	}
	if _, ok := got["REMOVED"]; ok {
		t.Error("removed secret still exported")
	}
	if got["KEPT"] != "new" || got["UNRELATED"] != "keep" {
		t.Error("fresh or unrelated environment lost")
	}
	if got["SCHAIN_KEYS"] != `["KEPT"]` {
		t.Errorf("injected key inventory not refreshed: %q", got["SCHAIN_KEYS"])
	}

}
