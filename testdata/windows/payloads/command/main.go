package main

import (
	"fmt"
	"os"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: command-probe.exe <marker-path>")
		os.Exit(2)
	}
	if err := os.WriteFile(os.Args[1], []byte("remoteexec command fixture\r\n"), 0o600); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
