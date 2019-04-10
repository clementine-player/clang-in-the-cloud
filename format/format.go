package format

import (
	"fmt"
	"io"
	"io/ioutil"

	"github.com/clementine-player/clang-in-the-cloud/format/formatters"
	"github.com/sourcegraph/go-diff/diff"
)

func FormatDiff(r io.Reader, hunks []*diff.Hunk, filename string) ([]byte, error) {
	fmter := formatters.FormatDiffFunc(filename)
	if fmter != nil {
		return fmter(r, hunks)
	}
	data, _ := ioutil.ReadAll(r)
	return data, fmt.Errorf("No formatter for file: %s", filename)
}

func FormatFile(r io.Reader, filename string) ([]byte, error) {
	fmter := formatters.FormatFunc(filename)
	if fmter != nil {
		return fmter(r)
	}
	data, _ := ioutil.ReadAll(r)
	return data, fmt.Errorf("No formatter for file: %s", filename)
}

// Format tries formatting just the changed lines if supported, otherwise the whole file.
func Format(r io.Reader, hunks []*diff.Hunk, filename string) ([]byte, error) {
	diffFmter := formatters.FormatDiffFunc(filename)
	if diffFmter != nil {
		return diffFmter(r, hunks)
	} else {
		return FormatFile(r, filename)
	}
}

func CanFormat(filename string) bool {
	return formatters.FormatFunc(filename) != nil
}
