package config

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

func Load(path, cwd string) (Config, error) {
	var cfg Config

	if cwd == "" {
		var err error
		cwd, err = os.Getwd()
		if err != nil {
			return Config{}, fmt.Errorf("determine cwd: %w", err)
		}
	}

	configPath := path
	if !filepath.IsAbs(configPath) {
		configPath = filepath.Join(cwd, configPath)
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		return Config{}, fmt.Errorf("read config %q: %w", configPath, err)
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return Config{}, fmt.Errorf("decode config %q: %w", configPath, err)
	}

	if cfg.Sandbox.Workdir != "" && !filepath.IsAbs(cfg.Sandbox.Workdir) {
		cfg.Sandbox.Workdir = filepath.Join(cwd, cfg.Sandbox.Workdir)
	}

	return cfg, nil
}

func ValidateRuntime(cfg Config) error {
	if strings.EqualFold(cfg.Network.TransparentProxy.Mode, "mitm") {
		return errors.New("network.transparent_proxy.mode=mitm is not supported by runtime yet")
	}
	return nil
}
