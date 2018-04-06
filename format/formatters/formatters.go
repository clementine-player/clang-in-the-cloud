package formatters

import (
	"io"
	"strings"

	"sourcegraph.com/sourcegraph/go-diff/diff"
)

type formatFunc func(io.Reader) ([]byte, error)
type formatDiffFunc func(io.Reader, []*diff.Hunk) ([]byte, error)

var fmters = map[string]formatFunc{
	".cpp": FormatCPPFile,
	".cxx": FormatCPPFile,
	".h":   FormatCPPFile,
	".go":  FormatGoFile,
}

var diffFmters = map[string]formatDiffFunc{
	".cpp": FormatCPP,
	".cxx": FormatCPP,
	".h":   FormatCPP,
}

func FormatFunc(filename string) formatFunc {
	for k, v := range fmters {
		if strings.HasSuffix(filename, k) {
			return v
		}
	}
	return nil
}

func FormatDiffFunc(filename string) formatDiffFunc {
	for k, v := range diffFmters {
		if strings.HasSuffix(filename, k) {
			return v
		}
	}
	return nil
}
