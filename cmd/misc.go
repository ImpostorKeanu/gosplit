package main

import (
	"fmt"
	"io"
	"os"
)

const (
	flagRequiredMsg = "error marking flag required"
)

// prExit, when err != nil, prints msg to stderr and exits
// with a status code of 1
func prExit(err error, msg string) {
	if err != nil {
		println(fmt.Sprintf("%s:", msg), err)
		os.Exit(1)
	}
}

// closeWriter closes writers that implement io.Closer.
func closeWriter(writer io.Writer) {
	if closer, ok := writer.(io.Closer); ok {
		closer.Close()
	}
}
