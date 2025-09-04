package matcher

import (
	"net"

	"github.com/dlclark/regexp2"
	"go.uber.org/zap"
)

type RegexMatcherConfig struct {
	Pattern string `yaml:"pattern"`
}

type RegexMatcher struct {
	re *regexp2.Regexp
}

func NewRegexMatcher(cfg *RegexMatcherConfig) (*RegexMatcher, error) {
	re, err := regexp2.Compile(cfg.Pattern, 0)
	if err != nil {
		return nil, err
	}
	return &RegexMatcher{re: re}, nil
}

func (m *RegexMatcher) Match(conn net.Conn, data []byte) bool {
	match, err := m.re.MatchString(string(data))
	if err != nil {
		zap.L().Error("regex match error", zap.Error(err))
		return false
	}
	return match
}
