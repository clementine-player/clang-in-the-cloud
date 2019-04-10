package formatters

import (
	"bytes"
	"flag"
	"fmt"
	"io"
	"log"
	"os/exec"

	"github.com/sourcegraph/go-diff/diff"
)

var (
	googleJavaFormat = flag.String("google-java-format", "google-java-format-1.5.jar",
		"Path to google java format jar to use")
	java = flag.String("java", "java", "Path to java binary")
)

func FormatJava(r io.Reader, hunks []*diff.Hunk) ([]byte, error) {
	stdout := bytes.Buffer{}
	stderr := bytes.Buffer{}

	args := []string{"-jar", *googleJavaFormat}
	for _, linePair := range findLineRanges(hunks) {
		args = append(args, "--lines")
		args = append(args, fmt.Sprintf("%d:%d", linePair.Start, linePair.End))
	}
	args = append(args, "-")
	log.Printf("Args: %v", args)
	cmd := exec.Command(*java, args...)
	cmd.Stdin = r
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr

	err := cmd.Run()
	if err != nil {
		log.Printf("google-java-format failed: %v", err)
		return nil, fmt.Errorf("google-java-format: %s", stderr.String())
	}
	return stdout.Bytes(), nil
}

func FormatJavaFile(r io.Reader) ([]byte, error) {
	return FormatJava(r, []*diff.Hunk{})
}
