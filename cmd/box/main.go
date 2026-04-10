package main

import "os"

type noopExecutor struct{}

func (noopExecutor) Run(runRequest) error {
	return nil
}

func main() {
	cmd := newRootCommand(deps{
		executor: noopExecutor{},
	})
	if err := cmd.Execute(); err != nil {
		os.Exit(1)
	}
}

