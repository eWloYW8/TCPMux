package matcher

import (
	"bytes"
	"fmt"

	"github.com/eWloYW8/TCPMux/transport"
	"gopkg.in/yaml.v3"
)

type SubstringMatcherConfig struct {
	Offset int    `yaml:"offset"`
	Value  string `yaml:"value"`
}

type SubstringMatcher struct {
	config *SubstringMatcherConfig
}

func init() {
	Register("substring", newSubstringMatcher)
}

func newSubstringMatcher(parameter yaml.Node) (Matcher, error) {
	cfg := &SubstringMatcherConfig{}
	if err := parameter.Decode(cfg); err != nil {
		return nil, fmt.Errorf("failed to decode substring matcher config: %v", err)
	}
	return NewSubstringMatcher(cfg), nil
}

func NewSubstringMatcher(cfg *SubstringMatcherConfig) *SubstringMatcher {
	return &SubstringMatcher{config: cfg}
}

func (m *SubstringMatcher) Match(conn *transport.ClientConnection) bool {
	data := make([]byte, 8192)
	conn.ReadUnconsumed(data)
	if m.config.Offset < 0 || m.config.Offset > len(data) {
		return false
	}
	return bytes.Contains(data[m.config.Offset:], []byte(m.config.Value))
}
