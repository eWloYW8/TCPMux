package matcher

import (
	"fmt"
	"net"

	"gopkg.in/yaml.v3"
)

type TimeoutMatcherConfig struct {
	Timeout int `yaml:"timeout"`
}

type TimeoutMatcher struct {
	config *TimeoutMatcherConfig
}

func init() {
	Register("timeout", newTimeoutMatcher)
}

func newTimeoutMatcher(parameter yaml.Node) (Matcher, error) {
	cfg := &TimeoutMatcherConfig{}
	if err := parameter.Decode(cfg); err != nil {
		return nil, fmt.Errorf("failed to decode timeout matcher config: %v", err)
	}
	return NewTimeoutMatcher(cfg), nil
}

func NewTimeoutMatcher(cfg *TimeoutMatcherConfig) *TimeoutMatcher {
	return &TimeoutMatcher{config: cfg}
}

func (m *TimeoutMatcher) Match(conn net.Conn, data []byte) bool {
	return true
}
