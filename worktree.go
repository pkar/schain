package main

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/tabwriter"
)

// A linked git worktree is a second checkout of the same repository at
// another path. Vault files are untracked, so a fresh worktree starts with
// none of the per-directory vaults its main checkout has. schain finds the
// main checkout by reading git's own files, no `git` binary and no shell:
//
//	<worktree>/.git            a file: "gitdir: <main>/.git/worktrees/<name>"
//	<that dir>/commondir       "../.." -> <main>/.git, whose parent is <main>
//
// Submodules use the same .git-file indirection but have no commondir, so
// requiring commondir keeps them out.

type worktree struct {
	root string // the linked checkout
	main string // the checkout it was created from
}

func findWorktree(dir string) *worktree {
	blob, err := os.ReadFile(filepath.Join(dir, ".git"))
	if err != nil {
		return nil // absent, or a directory: this is a normal checkout
	}
	rest, ok := strings.CutPrefix(strings.TrimSpace(string(blob)), "gitdir:")
	if !ok {
		return nil
	}
	gitDir := strings.TrimSpace(rest)
	if !filepath.IsAbs(gitDir) {
		gitDir = filepath.Join(dir, gitDir)
	}
	common, err := os.ReadFile(filepath.Join(gitDir, "commondir"))
	if err != nil {
		return nil // submodule or something else, not a worktree
	}
	c := strings.TrimSpace(string(common))
	if !filepath.IsAbs(c) {
		c = filepath.Join(gitDir, c)
	}
	c = filepath.Clean(c)
	if filepath.Base(c) != ".git" {
		return nil // bare or --separate-git-dir: no main checkout to borrow from
	}
	main := filepath.Dir(c)
	if resolved, err := filepath.EvalSymlinks(main); err == nil {
		main = resolved // match the physical paths the cwd walk produces
	}
	if main == dir {
		return nil
	}
	return &worktree{root: dir, main: main}
}

// findWorktreeFrom looks for a linked worktree at dir or any parent.
func findWorktreeFrom(dir string) *worktree {
	for {
		if w := findWorktree(dir); w != nil {
			return w
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return nil
		}
		dir = parent
	}
}

// cmdWorktree reports which vaults this worktree uses and where each one
// lives, so "it resolved to the wrong value" is visible before it bites.
func cmdWorktree(args []string) error {
	if len(args) > 0 {
		return fmt.Errorf("usage: schain worktree")
	}
	cwd, err := workDir()
	if err != nil {
		return err
	}
	wt := findWorktreeFrom(cwd)
	if wt == nil {
		return fmt.Errorf("not in a linked git worktree (nothing to borrow from)")
	}
	resolveVaults() // surfaces the unreachable-ancestor warning, if any
	fmt.Printf("worktree:      %s\n", wt.root)
	fmt.Printf("main checkout: %s\n", wt.main)

	fromMain, err := walkVaults(wt.main, true)
	if err != nil {
		return err
	}
	fromWT, err := walkVaults(wt.root, true)
	if err != nil {
		return err
	}
	rels := map[string][2]bool{} // rel path -> {in main, in worktree}
	mark := func(paths []string, root string, i int) {
		for _, p := range paths {
			rel, err := filepath.Rel(root, p)
			if err != nil {
				continue
			}
			e := rels[rel]
			e[i] = true
			rels[rel] = e
		}
	}
	mark(fromMain, wt.main, 0)
	mark(fromWT, wt.root, 1)
	if len(rels) == 0 {
		fmt.Println("no vaults in either checkout")
		return nil
	}
	keys := make([]string, 0, len(rels))
	for k := range rels {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	w := tabwriter.NewWriter(os.Stdout, 0, 0, 2, ' ', 0)
	for _, k := range keys {
		switch e := rels[k]; {
		case e[0] && e[1]:
			fmt.Fprintf(w, "  %s\tlocal, shadows the main checkout\n", k)
		case e[1]:
			fmt.Fprintf(w, "  %s\tlocal to this worktree\n", k)
		default:
			fmt.Fprintf(w, "  %s\tfrom the main checkout\n", k)
		}
	}
	return w.Flush()
}
