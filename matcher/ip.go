package matcher

import (
	"fmt"
	"net"
	"strings"

	"github.com/eWloYW8/TCPMux/transport"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

type IPMatcherConfig struct {
	CIDRs []string `yaml:"CIDRs"`
	Mode  string   `yaml:"mode"`
}

type IPMatcher struct {
	ipNets []*net.IPNet
	mode   string
}

func init() {
	Register("ip", newIPMatcher)
}

func newIPMatcher(parameter yaml.Node) (Matcher, error) {
	cfg := &IPMatcherConfig{}
	if err := parameter.Decode(cfg); err != nil {
		return nil, fmt.Errorf("failed to decode IP matcher config: %v", err)
	}

	if cfg.Mode == "" {
		cfg.Mode = "allow"
	}
	cfg.Mode = strings.ToLower(cfg.Mode)
	if cfg.Mode != "allow" && cfg.Mode != "deny" {
		return nil, fmt.Errorf("invalid mode '%s', must be 'allow' or 'deny'", cfg.Mode)
	}

	return NewIPMatcher(cfg)
}

func NewIPMatcher(cfg *IPMatcherConfig) (*IPMatcher, error) {
	if len(cfg.CIDRs) == 0 {
		return nil, fmt.Errorf("CIDRs list cannot be empty for ip matcher")
	}

	matcher := &IPMatcher{
		ipNets: make([]*net.IPNet, 0, len(cfg.CIDRs)),
		mode:   cfg.Mode,
	}

	for _, cidr := range cfg.CIDRs {
		_, ipNet, err := net.ParseCIDR(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR notation '%s': %v", cidr, err)
		}
		matcher.ipNets = append(matcher.ipNets, ipNet)
	}
	return matcher, nil
}

func (m *IPMatcher) Match(conn *transport.ClientConnection) bool {
	logger := conn.GetLogger()
	clientIP, _, err := net.SplitHostPort(conn.RemoteAddr().String())
	if err != nil {
		logger.Debug("Failed to get client IP from connection", zap.Error(err))
		return false
	}
	ip := net.ParseIP(clientIP)
	if ip == nil {
		logger.Debug("Failed to parse client IP")
		return false
	}

	isMatch := false
	for _, ipNet := range m.ipNets {
		if ipNet.Contains(ip) {
			isMatch = true
			break
		}
	}

	if m.mode == "allow" {
		if isMatch {
			logger.Debug("Client IP matched a configured CIDR (allow mode)")
		} else {
			logger.Debug("Client IP did not match any configured CIDR (allow mode)")
		}
		return isMatch
	} else {
		if isMatch {
			logger.Debug("Client IP matched a configured CIDR (deny mode)")
		} else {
			logger.Debug("Client IP did not match any configured CIDR (deny mode)")
		}
		return !isMatch
	}
}
