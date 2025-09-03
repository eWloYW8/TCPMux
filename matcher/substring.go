package matcher

import (
	"bytes"
	"net"

	"github.com/eWloYW8/TCPMux/config"
)

type SubstringMatcher struct {
	rule *config.Rule
}

func NewSubstringMatcher(rule *config.Rule) *SubstringMatcher {
	return &SubstringMatcher{rule: rule}
}

func (m *SubstringMatcher) Match(conn net.Conn, data []byte) bool {
	if m.rule.Parameter.Offset < 0 || m.rule.Parameter.Offset > len(data) {
		return false
	}
	return bytes.Contains(data[m.rule.Parameter.Offset:], []byte(m.rule.Parameter.Value))
}
