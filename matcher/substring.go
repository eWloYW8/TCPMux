package matcher

import (
	"bytes"
	"net"
)

type SubstringMatcherConfig struct {
	Offset int    `yaml:"offset"`
	Value  string `yaml:"value"`
}

type SubstringMatcher struct {
	config *SubstringMatcherConfig
}

func NewSubstringMatcher(cfg *SubstringMatcherConfig) *SubstringMatcher {
	return &SubstringMatcher{config: cfg}
}

func (m *SubstringMatcher) Match(conn net.Conn, data []byte) bool {
	if m.config.Offset < 0 || m.config.Offset > len(data) {
		return false
	}
	return bytes.Contains(data[m.config.Offset:], []byte(m.config.Value))
}
