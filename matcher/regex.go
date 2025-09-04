package matcher

import (
	"fmt"
	"net"

	"github.com/dlclark/regexp2"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

type RegexMatcherConfig struct {
	Pattern string `yaml:"pattern"`
}

type RegexMatcher struct {
	re *regexp2.Regexp
}

func init() {
	Register("regex", newRegexMatcher)
}

func newRegexMatcher(parameter yaml.Node) (Matcher, error) {
	cfg := &RegexMatcherConfig{}
	if err := parameter.Decode(cfg); err != nil {
		return nil, fmt.Errorf("failed to decode regex matcher config: %v", err)
	}
	return NewRegexMatcher(cfg)
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
