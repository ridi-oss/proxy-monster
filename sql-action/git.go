package main

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os/exec"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// addedFiles returns the files head adds directly under dir whose name matches re, relative to the merge base
// of base and head. A matching file that already exists on base must not change. A file's key is re's `key`
// group, or its whole name when re has none.
func addedFiles(ctx context.Context, gitDir, dir string, re *regexp.Regexp, base, head string) ([]fileInput, error) {
	dir = path.Clean(filepath.ToSlash(dir))
	if path.IsAbs(dir) || filepath.IsAbs(dir) || dir == ".." || strings.HasPrefix(dir, "../") {
		return nil, fmt.Errorf("invalid --dir %q: must be inside the repository", dir)
	}
	for _, sha := range []string{base, head} {
		if _, err := resolveCommit(ctx, gitDir, sha); err != nil {
			return nil, err
		}
	}
	diff, err := git(ctx, gitDir, "-c", "core.quotepath=off", "diff", "--no-ext-diff", "--no-color", "-M",
		"--name-status", "-z", base+"..."+head)
	if err != nil {
		return nil, err
	}
	matches := func(p string) bool { return path.Dir(p) == dir && re.MatchString(path.Base(p)) }

	var added, problems []string
	fields := strings.Split(strings.TrimSuffix(string(diff), "\x00"), "\x00")
	for i := 0; i < len(fields); {
		status := fields[i]
		if status == "" {
			i++
			continue
		}
		kind := status[0]
		n := 1
		if kind == 'R' || kind == 'C' {
			n = 2
		}
		if i+n >= len(fields) {
			return nil, fmt.Errorf("unexpected git diff output near %q", status)
		}
		paths := fields[i+1 : i+1+n]
		i += 1 + n
		switch kind {
		case 'A':
			if matches(paths[0]) {
				added = append(added, paths[0])
			}
		case 'M', 'T':
			if matches(paths[0]) {
				problems = append(problems, "modified "+paths[0])
			}
		case 'D':
			if matches(paths[0]) {
				problems = append(problems, "deleted "+paths[0])
			}
		case 'R':
			score, _ := strconv.Atoi(status[1:])
			if matches(paths[1]) && score < 100 {
				problems = append(problems, "renamed and modified "+paths[0]+" -> "+paths[1])
			}
		case 'C':
			if matches(paths[1]) {
				added = append(added, paths[1])
			}
		}
	}
	if len(problems) > 0 {
		return nil, errors.New("files already merged must not change:\n  " + strings.Join(problems, "\n  "))
	}
	sort.Strings(added)
	keyGroup := re.SubexpIndex("key")
	files := make([]fileInput, 0, len(added))
	for _, p := range added {
		content, err := git(ctx, gitDir, "show", head+":"+p)
		if err != nil {
			return nil, err
		}
		key := path.Base(p)
		if keyGroup >= 0 {
			if m := re.FindStringSubmatch(key); m != nil && m[keyGroup] != "" {
				key = m[keyGroup]
			}
		}
		files = append(files, fileInput{Path: p, Key: key, Content: string(content)})
	}
	return files, nil
}

// resolveCommit returns the full SHA of the commit rev names.
func resolveCommit(ctx context.Context, gitDir, rev string) (string, error) {
	if strings.HasPrefix(rev, "-") {
		return "", fmt.Errorf("invalid commit %q", rev)
	}
	out, err := git(ctx, gitDir, "rev-parse", "--verify", "--quiet", rev+"^{commit}")
	if err != nil {
		return "", fmt.Errorf("commit %s not found; check out with fetch-depth: 0", rev)
	}
	return strings.TrimSpace(string(out)), nil
}

func git(ctx context.Context, dir string, args ...string) ([]byte, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return nil, fmt.Errorf("git %s: %w: %s", strings.Join(args, " "), err, strings.TrimSpace(stderr.String()))
	}
	return out, nil
}
