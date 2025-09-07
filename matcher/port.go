package matcher

import (
	"fmt"
	"net"
	"strconv"

	"github.com/eWloYW8/TCPMux/transport"
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

func (m *PortMatcher) Match(conn *transport.ClientConnection) bool {
	logger := conn.GetLogger()
	_, portStr, err := net.SplitHostPort(conn.LocalAddr().String())
	if err != nil {
		logger.Debug("Failed to get local port from connection", zap.Error(err))
		return false
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		logger.Debug("Failed to parse local port")
		return false
	}

	if _, ok := m.ports[port]; ok {
		logger.Debug("Connection port matched a configured port")
		return true
	}

	logger.Debug("Connection port did not match any configured port")
	return false
}
