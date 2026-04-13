package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"gvisor-net/internal/envoy"
)

func main() {
	if err := run(context.Background(), os.Args[1:], func(ctx context.Context, outputPath string, platform string) error {
		return envoy.StageBundledBinary(ctx, envoy.StageRequest{
			OutputPath: outputPath,
			Platform:   platform,
		})
	}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, stage func(context.Context, string, string) error) error {
	fs := flag.NewFlagSet("envoypack", flag.ContinueOnError)
	fs.SetOutput(os.Stderr)

	var outputPath string
	var platform string
	fs.StringVar(&outputPath, "output", "", "path to write the staged envoy binary")
	fs.StringVar(&platform, "platform", "", "container platform, e.g. linux/amd64")
	if err := fs.Parse(filterArgs(args)); err != nil {
		return err
	}
	if outputPath == "" {
		return fmt.Errorf("--output is required")
	}
	return stage(ctx, outputPath, platform)
}

func filterArgs(args []string) []string {
	if len(args) > 0 && args[0] == "--" {
		return args[1:]
	}
	return args
}
