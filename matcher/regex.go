package matcher

import (
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
	match, err := m.re.MatchString(string(data))
	if err != nil {
		zap.L().Error("regex match error", zap.Error(err))
		return false
	}
	return match
}
