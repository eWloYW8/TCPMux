// FILE: config/config.go
package config

import (
	"os"

	"gopkg.in/yaml.v3"
)

type Config struct {
	TLS     TLSConfig     `yaml:"tls"`
	Rules   []Rule        `yaml:"rules"`
	Logging LoggingConfig `yaml:"logging"`
	Listen  []string      `yaml:"listen"`
}

type TLSConfig struct {
	Enabled bool        `yaml:"enabled"`
	Config  []SNIConfig `yaml:"config"`
}

type SNIConfig struct {
	SNI  string `yaml:"sni"`
	Cert string `yaml:"cert"`
	Key  string `yaml:"key"`
}

type MatcherParameter struct {
	Offset  int    `yaml:"offset"`
	Value   string `yaml:"value"`
	Pattern string `yaml:"pattern"`
	Timeout int    `yaml:"timeout"`
}

type Rule struct {
	Name        string           `yaml:"name"`
	Type        string           `yaml:"type"`
	TLSRequired bool             `yaml:"tls_required"`
	Script      string           `yaml:"script"`
	Parameter   MatcherParameter `yaml:"parameter"`
	Handler     HandlerConfig    `yaml:"handler"`
}

type HandlerConfig struct {
	Name    string `yaml:"name"`
	Type    string `yaml:"type"`
	Backend string `yaml:"backend"`
	TLS     bool   `yaml:"tls"`
	Path    string `yaml:"path"`
	Timeout int    `yaml:"timeout"`
}

type LoggingConfig struct {
	Level  string `yaml:"level"`
	Stderr bool   `yaml:"stderr"`
	File   string `yaml:"file"`
	Format string `yaml:"format"`
}

func LoadConfig(path string) (*Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var cfg Config
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return nil, err
	}

	if cfg.Logging.Format == "" {
		cfg.Logging.Format = "console"
	}

	return &cfg, nil
}
