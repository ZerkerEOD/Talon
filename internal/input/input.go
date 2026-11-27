// Package input loads line-oriented input files (hosts, users, passwords).
package input

import (
	"os"
	"strings"
)

// Lines reads a file and returns its non-empty, whitespace-trimmed lines.
// Trailing "\r" (Windows CRLF files) and blank lines are dropped, so a
// trailing newline can never produce an empty "" entry.
func Lines(path string) ([]string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, ln := range strings.Split(string(b), "\n") {
		ln = strings.TrimRight(ln, "\r")
		ln = strings.TrimSpace(ln)
		if ln != "" {
			out = append(out, ln)
		}
	}
	return out, nil
}
