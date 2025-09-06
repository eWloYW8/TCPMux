package matcher

import (
	"fmt"

	"github.com/eWloYW8/TCPMux/transport"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

type OrMatcher struct {
	matchers []Matcher
}

func init() {
	Register("or", newOrMatcher)
}

func newOrMatcher(parameter yaml.Node) (Matcher, error) {
	cfg := &LogicMatcherConfig{}
	if err := parameter.Decode(cfg); err != nil {
		return nil, fmt.Errorf("failed to decode or matcher config: %v", err)
	}

	var matchers []Matcher
	for _, subMatcherCfg := range cfg.Matchers {
		m, err := NewMatcher(subMatcherCfg.Type, subMatcherCfg.Parameter)
		if err != nil {
			return nil, fmt.Errorf("failed to create sub-matcher of type '%s': %v", subMatcherCfg.Type, err)
		}
		matchers = append(matchers, m)
	}

	return &OrMatcher{matchers: matchers}, nil
}

func (m *OrMatcher) Match(conn *transport.BufferedConn) bool {
	for i, subMatcher := range m.matchers {
		if subMatcher.Match(conn) {
			zap.L().Debug("Or matcher succeeded on sub-matcher", zap.Int("index", i))
			return true
		}
	}
	zap.L().Debug("Or matcher failed, no sub-matchers matched")
	return false
}
