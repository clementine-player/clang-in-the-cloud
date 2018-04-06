package formatters

import (
	"fmt"
	"io"
	"io/ioutil"

	gofmt "go/format"
)

func FormatGoFile(r io.Reader) ([]byte, error) {
	data, err := ioutil.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("Failed to read file: %v", err)
	}
	return gofmt.Source(data)
}
