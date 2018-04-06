package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/clementine-player/clang-in-the-cloud/format"
)

var file = flag.String("file", "", "")

func main() {
	flag.Parse()

	f, _ := os.Open(*file)
	formatted, _ := format.FormatFile(f, *file)
	fmt.Printf("%s", formatted)
}
