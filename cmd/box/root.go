package main

import (
	"github.com/spf13/cobra"
)

func newRootCommand(d deps) *cobra.Command {
	d = withDefaults(d)

	var configPath string

	root := &cobra.Command{
		Use:   "box",
		Short: "box CLI",
		Args:  cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			return runPayload(d, configPath, args)
		},
	}
	root.SilenceUsage = true
	root.PersistentFlags().StringVar(&configPath, "config", "box.yaml", "path to config file")
	root.AddCommand(newRunCommand(d, &configPath))

	return root
}
