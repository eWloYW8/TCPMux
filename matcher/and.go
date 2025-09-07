package matcher

import (
	"fmt"

	"github.com/eWloYW8/TCPMux/transport"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

type LogicMatcherConfig struct {
	Matchers []struct {
		Type      string    `yaml:"type"`
		Parameter yaml.Node `yaml:"parameter"`
	} `yaml:"matchers"`
}

type AndMatcher struct {
	matchers []Matcher
}

func init() {
	Register("and", newAndMatcher)
}

func newAndMatcher(parameter yaml.Node) (Matcher, error) {
	cfg := &LogicMatcherConfig{}
	if err := parameter.Decode(cfg); err != nil {
		return nil, fmt.Errorf("failed to decode and matcher config: %v", err)
	}

	var matchers []Matcher
	for _, subMatcherCfg := range cfg.Matchers {
		m, err := NewMatcher(subMatcherCfg.Type, subMatcherCfg.Parameter)
		if err != nil {
			return nil, fmt.Errorf("failed to create sub-matcher of type '%s': %v", subMatcherCfg.Type, err)
		}
		matchers = append(matchers, m)
	}

	return &AndMatcher{matchers: matchers}, nil
}

func (m *AndMatcher) Match(conn *transport.ClientConnection) bool {
	logger := conn.GetLogger()
	for i, subMatcher := range m.matchers {
		if !subMatcher.Match(conn) {
			logger.Debug("And matcher failed on sub-matcher", zap.Int("index", i))
			return false
		}
	}
	logger.Info("And matcher succeeded, all sub-matchers matched")
	return true
}
