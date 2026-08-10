package main

import (
	"fmt"
	"os"
	"sort"
	"strconv"
	"text/tabwriter"
	"time"
)

// Every set or unset keeps the value it replaced inside the vault, capped
// per key, so a rotation that breaks something can be undone. Old values
// are never printed: they are restored in place, which is the one thing
// you actually need them for. History is a property of a single vault
// file, so these commands act on the nearest vault, never the chain.

const (
	historyKey     = "SCHAIN_HISTORY" // reserved: versions kept per key
	defaultHistory = 3
)

const historyUsage = `usage:
  schain history                 keys with history in the nearest vault
  schain history KEY             one key's timeline
  schain history revert KEY [N]  restore the value from N changes back (default 1)
  schain history on [N]          keep N past values per key (default ` + "3" + `)
  schain history off             stop recording (kept values stay; purge removes them)
  schain history purge [KEY...]  drop stored history`

func cmdHistory(args []string) error {
	verb := ""
	if len(args) > 0 {
		verb = args[0]
	}
	switch verb {
	case "revert":
		return historyRevert(args[1:])
	case "on", "off":
		return historySwitch(verb, args[1:])
	case "purge":
		return historyPurge(args[1:])
	case "-h", "--help":
		fmt.Println(historyUsage)
		return nil
	}
	if len(args) > 1 {
		return fmt.Errorf("%s", historyUsage)
	}
	return historyShow(verb)
}

// openNearest unlocks the vault these commands act on, warning first when
// that file lives in a worktree's main checkout.
func openNearest(write bool) (*vault, string, error) {
	path, err := mustFindVault()
	if err != nil {
		return nil, "", err
	}
	if write {
		noteTarget(path)
	}
	v, err := unlock(path)
	if err != nil {
		return nil, "", err
	}
	return v, path, nil
}

func historyShow(key string) error {
	v, path, err := openNearest(false)
	if err != nil {
		return err
	}
	defer v.close()
	if v.rev > 0 {
		fmt.Fprintf(os.Stderr, "%s, revision %d\n", display(path), v.rev)
	}
	if key != "" {
		return showKey(v, key)
	}
	if len(v.History) == 0 {
		if v.keep() == 0 {
			fmt.Fprintf(os.Stderr, "history is off for %s (turn on with: schain history on)\n", display(path))
			return nil
		}
		fmt.Fprintf(os.Stderr, "no history yet in %s\n", display(path))
		return nil
	}
	keys := make([]string, 0, len(v.History))
	for k := range v.History {
		keys = append(keys, k)
	}
	// Most recently changed first: what you came to look at.
	sort.Slice(keys, func(i, j int) bool {
		a, b := v.History[keys[i]][0].At, v.History[keys[j]][0].At
		if a != b {
			return a > b
		}
		return keys[i] < keys[j]
	})
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	fmt.Fprintln(w, "KEY\tKEPT\tLAST CHANGE\tBY")
	for _, k := range keys {
		last := v.History[k][0]
		state := ""
		if _, ok := v.Secrets[k]; !ok {
			state = " (unset)"
		}
		fmt.Fprintf(w, "%s%s\t%d\t%s\t%s\n", k, state, len(v.History[k]), stamp(last.At), last.By)
	}
	return w.Flush()
}

func showKey(v *vault, key string) error {
	revs := v.History[key]
	if len(revs) == 0 {
		if _, ok := v.Secrets[key]; !ok {
			return fmt.Errorf("no key %q", key)
		}
		fmt.Fprintf(os.Stderr, "no history for %s yet\n", key)
		return nil
	}
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	if _, ok := v.Secrets[key]; ok {
		fmt.Fprintf(w, "current\tsince %s\t%s\n", stamp(revs[0].At), revs[0].By)
	} else {
		fmt.Fprintf(w, "current\tunset %s\t%s\n", stamp(revs[0].At), revs[0].By)
	}
	for i, r := range revs {
		note := ""
		if r.Gone {
			note = "\tabsent: reverting removes the key"
		}
		fmt.Fprintf(w, "%d back\tuntil %s\t%s%s\n", i+1, stamp(r.At), r.By, note)
	}
	if err := w.Flush(); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "values are not shown; restore one with: schain history revert %s [N]\n", key)
	return nil
}

func historyRevert(args []string) error {
	if len(args) == 0 || len(args) > 2 {
		return fmt.Errorf("usage: schain history revert KEY [N]")
	}
	key := args[0]
	back := 1
	if len(args) == 2 {
		n, err := strconv.Atoi(args[1])
		if err != nil || n < 1 {
			return fmt.Errorf("bad step %q (1 means the previous value)", args[1])
		}
		back = n
	}
	v, path, err := openNearest(true)
	if err != nil {
		return err
	}
	defer v.close()
	revs := v.History[key]
	if len(revs) == 0 {
		return fmt.Errorf("no history for %q in %s", key, display(path))
	}
	if back > len(revs) {
		return fmt.Errorf("only %d version(s) kept for %q", len(revs), key)
	}
	target := revs[back-1]
	cur, live := v.Secrets[key]
	// Reverting is an ordinary change, so the value it replaces is kept
	// too and the revert can itself be reverted. That also means the step
	// count shifts afterwards: read `schain history KEY` again before
	// stepping back further.
	switch {
	case target.Gone && !live:
		return fmt.Errorf("%q is already unset", key)
	case !target.Gone && live && cur == target.Val:
		fmt.Fprintf(os.Stderr, "schain: %s already holds the value from %s; nothing changed\n", key, stamp(target.At))
		return nil
	case target.Gone:
		v.drop(key)
		fmt.Fprintf(os.Stderr, "schain: %s removed (it did not exist as of %s)\n", key, stamp(target.At))
	default:
		v.put(key, target.Val)
		fmt.Fprintf(os.Stderr, "schain: %s restored to the value from %s\n", key, stamp(target.At))
	}
	if err := v.save(path); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "schain: undo with: schain history revert %s\n", key)
	return nil
}

func historySwitch(verb string, args []string) error {
	n := defaultHistory
	if verb == "off" {
		if len(args) > 0 {
			return fmt.Errorf("usage: schain history off")
		}
		n = 0
	} else if len(args) == 1 {
		got, err := strconv.Atoi(args[0])
		if err != nil || got < 1 {
			return fmt.Errorf("bad count %q", args[0])
		}
		n = got
	} else if len(args) > 1 {
		return fmt.Errorf("usage: schain history on [N]")
	}
	v, path, err := openNearest(true)
	if err != nil {
		return err
	}
	defer v.close()
	if n == defaultHistory {
		delete(v.Secrets, historyKey)
	} else {
		v.Secrets[historyKey] = strconv.Itoa(n)
	}
	// Trim anything now over the limit; off keeps what is stored until
	// purge, which is the destructive step.
	for k, revs := range v.History {
		if len(revs) > n && n > 0 {
			v.History[k] = revs[:n]
		}
	}
	if err := v.save(path); err != nil {
		return err
	}
	if n == 0 {
		fmt.Fprintf(os.Stderr, "schain: history off for %s (%d key(s) still hold stored values; drop them with: schain history purge)\n",
			display(path), len(v.History))
		return nil
	}
	fmt.Fprintf(os.Stderr, "schain: keeping %d past value(s) per key in %s\n", n, display(path))
	return nil
}

func historyPurge(keys []string) error {
	v, path, err := openNearest(true)
	if err != nil {
		return err
	}
	defer v.close()
	n := 0
	if len(keys) == 0 {
		n = len(v.History)
		v.History = nil
	} else {
		for _, k := range keys {
			if _, ok := v.History[k]; !ok {
				return fmt.Errorf("no history for %q", k)
			}
			delete(v.History, k)
			n++
		}
		if len(v.History) == 0 {
			v.History = nil
		}
	}
	if err := v.save(path); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "schain: dropped history for %d key(s) in %s\n", n, display(path))
	return nil
}

func stamp(unix int64) string {
	return time.Unix(unix, 0).Local().Format("2006-01-02 15:04:05")
}
