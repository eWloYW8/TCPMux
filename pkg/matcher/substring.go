package matcher

import (
	"bytes"
	"net"

	"github.com/eWloYW8/TCPMux/pkg/config"
)

type SubstringMatcher struct {
	rule *config.Rule
}

func NewSubstringMatcher(rule *config.Rule) *SubstringMatcher {
	return &SubstringMatcher{rule: rule}
}

func (m *SubstringMatcher) Match(conn net.Conn, data []byte) bool {
	if m.rule.Offset < 0 || m.rule.Offset > len(data) {
		return false
	}
	return bytes.Contains(data[m.rule.Offset:], []byte(m.rule.Value))
}
