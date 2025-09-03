package matcher

import "net"

type TimeoutMatcherConfig struct {
	Timeout int `yaml:"timeout"`
}

type TimeoutMatcher struct {
	config *TimeoutMatcherConfig
}

func NewTimeoutMatcher(cfg *TimeoutMatcherConfig) *TimeoutMatcher {
	return &TimeoutMatcher{config: cfg}
}

func (m *TimeoutMatcher) Match(conn net.Conn, data []byte) bool {
	return true
}
