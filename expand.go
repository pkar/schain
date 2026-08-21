package main

import (
	"fmt"
	"os"
	"sort"
	"strings"
)

// A value is stored literally and handed to a child literally, with one
// opt-in exception: a key named in SCHAIN_EXPAND has its ${...}
// references resolved on the way out. Both halves of that sentence are
// deliberate.
//
// Opt-in, because expanding every value would quietly eat parts of the
// secrets a vault exists to hold. A bcrypt hash starts $2y$05$, and the
// usual expander reads that as three variables named 2y, 05 and whatever
// follows, none of which are set, and hands back a hash with holes in it.
// No error, and the first symptom is a 401 from a registry.
//
// A closed set with braces required, for the same reason: $2y is never a
// candidate because a bare $ means nothing here, and ${2y} is left as
// written because 2y is not one of these three.
//
//	${SCHAIN_DIR}  the directory of the vault this key is defined in
//	${HOME}        $HOME
//	${USER}        $USER
//
// SCHAIN_DIR is the point of it. $HOME makes a path portable between
// machines and leaves it wrong between two checkouts of one repo, which
// is how a worktree ends up pointed at the main checkout's kubeconfig.
// SCHAIN_DIR follows the vault, so a checkout with its own vault gets its
// own paths, and it means the vault's directory rather than the current
// one: a key defined three levels up expands to that level, not to
// wherever you happen to be standing, which would just be relative paths
// with extra steps.
//
// The list of expanded keys lives in a reserved key rather than in the
// file format, so a vault carrying one still opens in older builds; they
// export the value with the ${...} still in it, which is wrong in a way
// you can see.
const expandKey = "SCHAIN_EXPAND"

// expandNames is the closed set, in the order the docs list it. It has to
// agree with expandOne, and a test says so.
var expandNames = []string{"SCHAIN_DIR", "HOME", "USER"}

// expandOne resolves one name for a key defined in dir, and reports
// whether the name is one schain substitutes at all.
func expandOne(name, dir string) (string, bool) {
	switch name {
	case "SCHAIN_DIR":
		return dir, true
	case "HOME", "USER":
		return os.Getenv(name), true
	}
	return "", false
}

// scanRefs calls fn for every ${...} in val, with the name inside the
// braces and the bounds of the whole reference.
func scanRefs(val string, fn func(name string, start, end int)) {
	for i := 0; i+1 < len(val); i++ {
		if val[i] != '$' || val[i+1] != '{' {
			continue
		}
		j := strings.IndexByte(val[i+2:], '}')
		if j < 0 {
			return // unterminated: nothing after this can be a reference
		}
		fn(val[i+2:i+2+j], i, i+3+j)
		i += 2 + j
	}
}

// expandValue resolves the references in a value belonging to a vault in
// dir. A name outside the closed set is left exactly as written, since
// substituting nothing for it is how values get corrupted. A name inside
// the set that resolves to nothing is an error: the caller asked for
// expansion, so silently producing "/etc/kube.yaml" from "${HOME}/..." is
// not an option.
func expandValue(val, dir string) (string, error) {
	var b strings.Builder
	var err error
	last := 0
	scanRefs(val, func(name string, start, end int) {
		got, ok := expandOne(name, dir)
		if !ok {
			return
		}
		if got == "" && err == nil {
			err = fmt.Errorf("${%s} is not set", name)
		}
		b.WriteString(val[last:start])
		b.WriteString(got)
		last = end
	})
	switch {
	case err != nil:
		return "", err
	case last == 0:
		return val, nil
	}
	b.WriteString(val[last:])
	return b.String(), nil
}

// expandRefs lists the references in val that schain would substitute,
// in order, without repeats. It is what "ls -v" reports, so a key whose
// stored value differs from what a child sees says so.
func expandRefs(val string) []string {
	var refs []string
	seen := map[string]bool{}
	scanRefs(val, func(name string, _, _ int) {
		if _, ok := expandOne(name, ""); !ok || seen[name] {
			return
		}
		seen[name] = true
		refs = append(refs, "${"+name+"}")
	})
	return refs
}

// checkExpand vets a value before its key is marked expandable, so an
// unknown name is a complaint at the keyboard instead of a ${...} left
// sitting in a child's environment months later.
func checkExpand(key, val string) error {
	found := false
	var bad []string
	scanRefs(val, func(name string, _, _ int) {
		if _, ok := expandOne(name, ""); ok {
			found = true
			return
		}
		bad = append(bad, "${"+name+"}")
	})
	if len(bad) > 0 {
		return fmt.Errorf("%s: schain does not expand %s (only %s)",
			key, strings.Join(bad, ", "), strings.Join(expandNames, ", "))
	}
	if !found {
		return fmt.Errorf("%s: --expand needs a ${...} in the value (one of %s)",
			key, strings.Join(expandNames, ", "))
	}
	return nil
}

// expands reports whether k is one of this vault's expanded keys.
func (v *vault) expands(k string) bool {
	for _, name := range strings.Split(v.Secrets[expandKey], ",") {
		if name == k {
			return true
		}
	}
	return false
}

// setExpand adds k to this vault's expanded keys or takes it out. The
// list is a reserved key, so it is never exported and never recorded in
// history.
func (v *vault) setExpand(k string, on bool) {
	var names []string
	for _, name := range strings.Split(v.Secrets[expandKey], ",") {
		if name != "" && name != k {
			names = append(names, name)
		}
	}
	if on {
		names = append(names, k)
	}
	if len(names) == 0 {
		delete(v.Secrets, expandKey)
		return
	}
	sort.Strings(names)
	v.Secrets[expandKey] = strings.Join(names, ",")
}

// expandNote is what "ls -v" says about a key whose stored value is not
// what a child will see.
func expandNote(v *vault, k string) string {
	if v == nil || !v.expands(k) {
		return ""
	}
	if refs := expandRefs(v.Secrets[k]); len(refs) > 0 {
		return "expands " + strings.Join(refs, " ")
	}
	return "expanded"
}
