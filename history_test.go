package main

import (
	"os"
	"strings"
	"testing"
)

// clock makes revision timestamps deterministic and ordered.
func clock(t *testing.T) func() {
	t.Helper()
	old := nowUnix
	n := int64(1_700_000_000)
	nowUnix = func() int64 { n += 3600; return n }
	t.Cleanup(func() { nowUnix = old })
	return func() {}
}

func openAt(t *testing.T, path, pass string) *vault {
	t.Helper()
	v, err := openVault(path, []byte(pass))
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func magicOf(t *testing.T, path string) string {
	t.Helper()
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(blob[:magicLen])
}

// A replaced value is kept, survives a save/load round trip, and the file
// switches to the envelope format only once there is history to hold.
func TestHistoryRoundtrip(t *testing.T) {
	clock(t)
	path := testVaultPath(t)
	v, err := newVault([]byte("p"))
	if err != nil {
		t.Fatal(err)
	}
	v.Secrets["K"] = "one" // seeded without history
	if err := v.save(path); err != nil {
		t.Fatal(err)
	}
	if got := magicOf(t, path); got != magic {
		t.Errorf("magic = %q, want %q before any history", got, magic)
	}

	v = openAt(t, path, "p")
	v.put("K", "two")
	if err := v.save(path); err != nil {
		t.Fatal(err)
	}
	if got := magicOf(t, path); got != magic2 {
		t.Errorf("magic = %q, want %q once history exists", got, magic2)
	}

	v = openAt(t, path, "p")
	defer v.close()
	if v.Secrets["K"] != "two" {
		t.Errorf("K = %q, want two", v.Secrets["K"])
	}
	if h := v.History["K"]; len(h) != 1 || h[0].Val != "one" || h[0].At == 0 {
		t.Errorf("history = %+v, want the previous value with a timestamp", h)
	}
}

func TestHistoryCapAndOrder(t *testing.T) {
	clock(t)
	v, err := newVault([]byte("p"))
	if err != nil {
		t.Fatal(err)
	}
	for _, val := range []string{"a", "b", "c", "d", "e"} {
		v.put("K", val)
	}
	h := v.History["K"]
	if len(h) != defaultHistory {
		t.Fatalf("kept %d, want %d", len(h), defaultHistory)
	}
	// Newest first, and the oldest values fell off.
	for i, want := range []string{"d", "c", "b"} {
		if h[i].Val != want {
			t.Errorf("history[%d] = %q, want %q", i, h[i].Val, want)
		}
	}
	if h[0].At <= h[1].At {
		t.Error("timestamps not newest first")
	}
}

func TestHistoryRecordsCreationAndDeletion(t *testing.T) {
	clock(t)
	v, err := newVault([]byte("p"))
	if err != nil {
		t.Fatal(err)
	}
	v.put("K", "one")
	if h := v.History["K"]; len(h) != 1 || !h[0].Gone {
		t.Fatalf("creation not recorded as absent: %+v", h)
	}
	v.drop("K")
	if _, ok := v.Secrets["K"]; ok {
		t.Fatal("key not removed")
	}
	if h := v.History["K"]; len(h) != 2 || h[0].Val != "one" {
		t.Errorf("deletion did not keep the value: %+v", h)
	}
}

func TestHistorySkipsUnchangedAndReserved(t *testing.T) {
	clock(t)
	v, err := newVault([]byte("p"))
	if err != nil {
		t.Fatal(err)
	}
	v.Secrets["K"] = "same"
	v.put("K", "same")
	if len(v.History["K"]) != 0 {
		t.Error("rewriting the same value was recorded")
	}
	v.put(rootKey, "1")
	v.put(historyKey, "5")
	if len(v.History) != 0 {
		t.Errorf("reserved keys got history: %+v", v.History)
	}
}

func TestHistoryOffKeepsFormat(t *testing.T) {
	clock(t)
	path := testVaultPath(t)
	v, err := newVault([]byte("p"))
	if err != nil {
		t.Fatal(err)
	}
	v.Secrets[historyKey] = "0"
	v.put("K", "one")
	v.put("K", "two")
	if len(v.History) != 0 {
		t.Errorf("recorded with history off: %+v", v.History)
	}
	if err := v.save(path); err != nil {
		t.Fatal(err)
	}
	if got := magicOf(t, path); got != magic {
		t.Errorf("magic = %q, want %q so older builds can still read it", got, magic)
	}
}

func TestHistoryNotExported(t *testing.T) {
	clock(t)
	d := tree(t, "a")
	mkVault(t, d[0], "p", map[string]string{"A": "1", historyKey: "5", rootKey: "1"})
	stubCache(t, nil)
	stubPrompt(t, "p")
	t.Chdir(d[0])

	c := mustChain(t)
	defer c.close()
	wantSecrets(t, c.secrets(), map[string]string{"A": "1"})
}

func TestHistoryCloseWipes(t *testing.T) {
	clock(t)
	v, err := newVault([]byte("p"))
	if err != nil {
		t.Fatal(err)
	}
	v.put("K", "one")
	v.put("K", "two")
	v.close()
	for _, r := range v.History["K"] {
		if r.Val != "" {
			t.Errorf("history kept plaintext %q after close", r.Val)
		}
	}
}

// End-to-end through the commands: revert restores, and reverting the
// revert puts it back.
func TestHistoryRevertRoundTrip(t *testing.T) {
	clock(t)
	d := tree(t, "a")
	path := mkVault(t, d[0], "p", map[string]string{"TOKEN": "v1"})
	stubCache(t, map[string]string{path: "p"})
	stubPrompt(t)
	captureStderr(t)
	t.Chdir(d[0])

	if err := cmdSet([]string{"TOKEN=v2"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdHistory([]string{"revert", "TOKEN"}); err != nil {
		t.Fatal(err)
	}
	v := openAt(t, path, "p")
	if v.Secrets["TOKEN"] != "v1" {
		t.Fatalf("TOKEN = %q, want v1", v.Secrets["TOKEN"])
	}
	v.close()

	if err := cmdHistory([]string{"revert", "TOKEN"}); err != nil {
		t.Fatal(err)
	}
	v = openAt(t, path, "p")
	defer v.close()
	if v.Secrets["TOKEN"] != "v2" {
		t.Errorf("TOKEN = %q, want v2 after reverting the revert", v.Secrets["TOKEN"])
	}
}

func TestHistoryRevertSteps(t *testing.T) {
	clock(t)
	d := tree(t, "a")
	path := mkVault(t, d[0], "p", map[string]string{"K": "v1"})
	stubCache(t, map[string]string{path: "p"})
	stubPrompt(t)
	captureStderr(t)
	t.Chdir(d[0])

	for _, val := range []string{"v2", "v3", "v4"} {
		if err := cmdSet([]string{"K=" + val}); err != nil {
			t.Fatal(err)
		}
	}
	if err := cmdHistory([]string{"revert", "K", "3"}); err != nil {
		t.Fatal(err)
	}
	v := openAt(t, path, "p")
	defer v.close()
	if v.Secrets["K"] != "v1" {
		t.Errorf("K = %q, want v1", v.Secrets["K"])
	}
	if err := cmdHistory([]string{"revert", "K", "9"}); err == nil {
		t.Error("want an error stepping past what is kept")
	}
}

// Reverting to the value already in place changes nothing and says so,
// rather than reporting a restore that did not happen.
func TestHistoryRevertNoop(t *testing.T) {
	clock(t)
	d := tree(t, "a")
	path := mkVault(t, d[0], "p", map[string]string{"K": "v1"})
	stubCache(t, map[string]string{path: "p"})
	stubPrompt(t)
	stderr := captureStderr(t)
	t.Chdir(d[0])

	if err := cmdSet([]string{"K=v2"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdHistory([]string{"revert", "K"}); err != nil { // -> v1
		t.Fatal(err)
	}
	before := openAt(t, path, "p")
	depth := len(before.History["K"])
	before.close()

	if err := cmdHistory([]string{"revert", "K", "2"}); err != nil { // already v1
		t.Fatal(err)
	}
	if out := stderr(); !strings.Contains(out, "nothing changed") {
		t.Errorf("no-op revert did not say so: %q", out)
	}
	v := openAt(t, path, "p")
	defer v.close()
	if v.Secrets["K"] != "v1" {
		t.Errorf("K = %q, want v1", v.Secrets["K"])
	}
	if got := len(v.History["K"]); got != depth {
		t.Errorf("history depth = %d, want %d unchanged by a no-op", got, depth)
	}
}

// Reverting to the point before a key existed removes it again.
func TestHistoryRevertToAbsent(t *testing.T) {
	clock(t)
	d := tree(t, "a")
	path := mkVault(t, d[0], "p", map[string]string{"OTHER": "x"})
	stubCache(t, map[string]string{path: "p"})
	stubPrompt(t)
	captureStderr(t)
	t.Chdir(d[0])

	if err := cmdSet([]string{"NEW=oops"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdHistory([]string{"revert", "NEW"}); err != nil {
		t.Fatal(err)
	}
	v := openAt(t, path, "p")
	defer v.close()
	if _, ok := v.Secrets["NEW"]; ok {
		t.Error("reverting to absent left the key in place")
	}
}

// An unset key can be brought back.
func TestHistoryRevertUnset(t *testing.T) {
	clock(t)
	d := tree(t, "a")
	path := mkVault(t, d[0], "p", map[string]string{"K": "keepme"})
	stubCache(t, map[string]string{path: "p"})
	stubPrompt(t)
	captureStderr(t)
	t.Chdir(d[0])

	if err := cmdUnset([]string{"K"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdHistory([]string{"revert", "K"}); err != nil {
		t.Fatal(err)
	}
	v := openAt(t, path, "p")
	defer v.close()
	if v.Secrets["K"] != "keepme" {
		t.Errorf("K = %q, want keepme", v.Secrets["K"])
	}
}

func TestHistorySwitchAndPurge(t *testing.T) {
	clock(t)
	d := tree(t, "a")
	path := mkVault(t, d[0], "p", map[string]string{"K": "v1"})
	stubCache(t, map[string]string{path: "p"})
	stubPrompt(t)
	stderr := captureStderr(t)
	t.Chdir(d[0])

	if err := cmdSet([]string{"K=v2"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdHistory([]string{"off"}); err != nil {
		t.Fatal(err)
	}
	if err := cmdSet([]string{"K=v3"}); err != nil {
		t.Fatal(err)
	}
	v := openAt(t, path, "p")
	if n := len(v.History["K"]); n != 1 {
		t.Errorf("kept %d version(s) with history off, want the 1 already stored", n)
	}
	v.close()
	if out := stderr(); !strings.Contains(out, "purge") {
		t.Errorf("history off did not mention purge: %q", out)
	}

	if err := cmdHistory([]string{"purge"}); err != nil {
		t.Fatal(err)
	}
	v = openAt(t, path, "p")
	if len(v.History) != 0 {
		t.Errorf("purge left history: %+v", v.History)
	}
	v.close()
	if got := magicOf(t, path); got != magic {
		t.Errorf("magic = %q, want %q once history is off and purged", got, magic)
	}

	if err := cmdHistory([]string{"on", "7"}); err != nil {
		t.Fatal(err)
	}
	v = openAt(t, path, "p")
	defer v.close()
	if v.keep() != 7 {
		t.Errorf("keep = %d, want 7", v.keep())
	}
}

// The listing shows metadata only: no value ever reaches stdout.
func TestHistoryShowHidesValues(t *testing.T) {
	clock(t)
	d := tree(t, "a")
	path := mkVault(t, d[0], "p", map[string]string{"TOKEN": "supersecret"})
	stubCache(t, map[string]string{path: "p"})
	stubPrompt(t)
	captureStderr(t)
	t.Chdir(d[0])

	if err := cmdSet([]string{"TOKEN=rotated"}); err != nil {
		t.Fatal(err)
	}
	out := captureStdout(t)
	if err := cmdHistory(nil); err != nil {
		t.Fatal(err)
	}
	if err := cmdHistory([]string{"TOKEN"}); err != nil {
		t.Fatal(err)
	}
	got := out()
	for _, secret := range []string{"supersecret", "rotated"} {
		if strings.Contains(got, secret) {
			t.Errorf("history printed a value (%s):\n%s", secret, got)
		}
	}
	for _, want := range []string{"TOKEN", "LAST CHANGE", "current", "1 back"} {
		if !strings.Contains(got, want) {
			t.Errorf("output missing %q:\n%s", want, got)
		}
	}
}
