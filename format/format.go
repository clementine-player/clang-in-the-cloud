package format

import (
	"bytes"
	"flag"
	"fmt"
	"html/template"
	"io"
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

func Format(r io.Reader, hunks []*diff.Hunk) ([]byte, error) {
	stdout := bytes.Buffer{}
	stderr := bytes.Buffer{}

	args := []string{"-style", *style}
	for _, hunk := range hunks {
		args = append(args, "-lines")
		args = append(args, fmt.Sprintf("%d:%d", hunk.NewStartLine, hunk.NewStartLine+hunk.NewLines))
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
