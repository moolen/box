package main

import "os"

func main() {
	cmd := newRootCommand(deps{})
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}
