package main

import "github.com/spf13/cobra"

func newRunCommand(d deps, configPath *string) *cobra.Command {
	return &cobra.Command{
		Use:   "run",
		Short: "run payload command",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPayload(d, *configPath, args)
		},
	}
}
