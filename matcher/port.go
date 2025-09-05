package matcher

import (
	"fmt"
	"net"
	"strconv"

	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

type PortMatcherConfig struct {
	Ports []string `yaml:"ports"`
}

type PortMatcher struct {
	ports map[int]struct{}
}

func init() {
	Register("port", newPortMatcher)
}

func newPortMatcher(parameter yaml.Node) (Matcher, error) {
	cfg := &PortMatcherConfig{}
	if err := parameter.Decode(cfg); err != nil {
		return nil, fmt.Errorf("failed to decode port matcher config: %v", err)
	}
	return NewPortMatcher(cfg)
}

func NewPortMatcher(cfg *PortMatcherConfig) (*PortMatcher, error) {
	if len(cfg.Ports) == 0 {
		return nil, fmt.Errorf("ports list cannot be empty for port matcher")
	}

	ports := make(map[int]struct{}, len(cfg.Ports))
	for _, portStr := range cfg.Ports {
		port, err := strconv.Atoi(portStr)
		if err != nil {
			return nil, fmt.Errorf("invalid port '%s': %v", portStr, err)
		}
		ports[port] = struct{}{}
	}

	return &PortMatcher{ports: ports}, nil
}

func (m *PortMatcher) Match(conn net.Conn, data []byte) bool {
	_, portStr, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		zap.L().Debug("Failed to get local port from connection", zap.Error(err))
		return false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		zap.L().Debug("Failed to parse local port", zap.String("port_str", portStr))
		return false
	}

	if _, ok := m.ports[port]; ok {
		zap.L().Debug("Connection port matched a configured port", zap.Int("port", port))
		return true
	}

	zap.L().Debug("Connection port did not match any configured port", zap.Int("port", port))
	return false
}
