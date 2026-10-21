// Copyright 2026 rubyattack3r
// Licensed under the Apache License, Version 2.0.
package main

import (
	"fmt"
	"os"

	"github.com/rubyattack3r/remoteexec/cmd"
)

var version = "development"

func main() {
	if err := cmd.ExecuteVersion(version); err != nil {
		_, _ = fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
