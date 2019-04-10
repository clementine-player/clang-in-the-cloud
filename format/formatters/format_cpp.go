package formatters

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os/exec"

	"github.com/sourcegraph/go-diff/diff"
)

var (
	clang_format = flag.String("clang-format", "clang-format",
		"Path to the clang-format executable to use")
	style = flag.String("style",
		"{BasedOnStyle: Google, DerivePointerBinding: false, Standard: Cpp11}",
		"Style specification passed to clang-format")
)

func FormatCPP(r io.Reader, hunks []*diff.Hunk) ([]byte, error) {
	if !hasAnyAdditions(hunks) {
		in, _ := ioutil.ReadAll(r)
		return in, nil
	}

	stdout := bytes.Buffer{}
	stderr := bytes.Buffer{}

	args := []string{"-style", *style}
	for _, linePair := range findLineRanges(hunks) {
		args = append(args, "-lines")
		args = append(args, fmt.Sprintf("%d:%d", linePair.Start, linePair.End))
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

func FormatCPPFile(r io.Reader) ([]byte, error) {
	return FormatCPP(r, []*diff.Hunk{})
}
