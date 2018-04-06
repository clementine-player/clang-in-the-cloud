package formatters

import (
	"io"
	"strings"

	"sourcegraph.com/sourcegraph/go-diff/diff"
)

type formatFunc func(io.Reader) ([]byte, error)
type formatDiffFunc func(io.Reader, []*diff.Hunk) ([]byte, error)

var fmters = map[string]formatFunc{
	".cpp":  FormatCPPFile,
	".cxx":  FormatCPPFile,
	".h":    FormatCPPFile,
	".go":   FormatGoFile,
	".java": FormatJavaFile,
}

var diffFmters = map[string]formatDiffFunc{
	".cpp":  FormatCPP,
	".cxx":  FormatCPP,
	".h":    FormatCPP,
	".java": FormatJava,
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

func hasAdditions(hunk *diff.Hunk) bool {
	lines := strings.Split(string(hunk.Body), "\n")
	for _, line := range lines {
		if strings.HasPrefix(line, "+") {
			return true
		}
	}
	return false
}

func hasAnyAdditions(hunks []*diff.Hunk) bool {
	for _, hunk := range hunks {
		if hasAdditions(hunk) {
			return true
		}
	}
	return false
}

type Addition struct {
	Start int32
	End   int32
}

func findAdditions(hunk *diff.Hunk) []*Addition {
	lines := strings.Split(string(hunk.Body), "\n")
	var additions []*Addition
	var addition *Addition
	delta := 0
	for i, line := range lines {
		if strings.HasPrefix(line, "-") {
			delta = delta - 1
		}

		if addition == nil {
			if strings.HasPrefix(line, "+") {
				addition = &Addition{
					Start: int32(i + delta),
					End:   int32(i + delta),
				}
			}
		} else {
			if !strings.HasPrefix(line, "+") {
				addition.End = int32(i + delta - 1)
				additions = append(additions, addition)
				addition = nil
			}
		}
	}
	return additions
}

func findLineRanges(hunks []*diff.Hunk) []*Addition {
	var linePairs []*Addition
	for _, hunk := range hunks {
		for _, addition := range findAdditions(hunk) {
			linePairs = append(linePairs, &Addition{
				Start: hunk.NewStartLine + addition.Start,
				End:   hunk.NewStartLine + addition.End,
			})
		}
	}
	return linePairs
}
