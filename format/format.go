package format

import (
	"bytes"
	"flag"
	"fmt"
	"html/template"
	"io"
	"io/ioutil"
	"log"
	"os/exec"
	"strings"

	"sourcegraph.com/sourcegraph/go-diff/diff"
)

var (
	clang_format = flag.String("clang-format", "clang-format",
		"Path to the clang-format executable to use")
	style = flag.String("style",
		"{BasedOnStyle: Google, DerivePointerBinding: false, Standard: Cpp11}",
		"Style specification passed to clang-format")
)

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

func Format(r io.Reader, hunks []*diff.Hunk) ([]byte, error) {
	if !hasAnyAdditions(hunks) {
		in, _ := ioutil.ReadAll(r)
		return in, nil
	}

	stdout := bytes.Buffer{}
	stderr := bytes.Buffer{}

	args := []string{"-style", *style}
	for _, hunk := range hunks {
		for _, addition := range findAdditions(hunk) {
			args = append(args, "-lines")
			args = append(args,
				fmt.Sprintf("%d:%d", hunk.NewStartLine+addition.Start, hunk.NewStartLine+addition.End))
		}
	}
	log.Printf("Args: %v", args)

	cmd := exec.Command(*clang_format, args...)
	cmd.Stdin = r
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		log.Printf("clang-format failed: %v", err)
		return nil, fmt.Errorf("clang-format: %s", stderr.String())
	}
	return stdout.Bytes(), nil
}

func FormatFile(r io.Reader) ([]byte, error) {
	return Format(r, []*diff.Hunk{})
}

type Diff struct {
	Lines []Line
}

type Line struct {
	Add     bool
	Remove  bool
	Content string
}

func FormatAsHTML(diff string) (string, error) {
	t := template.Must(template.ParseFiles("diff_template.html"))
	var lines []Line
	for _, line := range strings.Split(diff, "\n") {
		lines = append(lines, Line{
			Add:     strings.HasPrefix(line, "+"),
			Remove:  strings.HasPrefix(line, "-"),
			Content: line,
		})
	}
	buf := bytes.Buffer{}
	err := t.Execute(&buf, Diff{Lines: lines})
	if err != nil {
		return "", err
	}
	return buf.String(), nil
}
