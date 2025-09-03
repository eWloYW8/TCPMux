package matcher

import (
	"fmt"
	"net"

	"github.com/eWloYW8/TCPMux/config"

	"github.com/dlclark/regexp2"
	"go.uber.org/zap"
)

type RegexMatcher struct {
	rule *config.Rule
	re   *regexp2.Regexp
}

func NewRegexMatcher(rule *config.Rule) (*RegexMatcher, error) {
	re, err := regexp2.Compile(rule.Parameter.Pattern, 0)
	if err != nil {
		return nil, err
	}
	return &RegexMatcher{rule: rule, re: re}, nil
}

func (m *RegexMatcher) Match(conn net.Conn, data []byte) bool {
	if m.rule.TLSRequired && conn.RemoteAddr().Network() != "tcp+tls" {
		return false
	}
	match, err := m.re.MatchString(string(data))
	if err != nil {
		zap.L().Error(fmt.Sprintf("regex match error: %v", err))
		return false
	}
	return match
}
