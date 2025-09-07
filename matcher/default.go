package matcher

import (
	"github.com/eWloYW8/TCPMux/transport"
	"gopkg.in/yaml.v3"
)

type DefaultMatcher struct{}

func init() {
	Register("default", newDefaultMatcher)
}

func newDefaultMatcher(parameter yaml.Node) (Matcher, error) {
	return NewDefaultMatcher(), nil
}

func NewDefaultMatcher() *DefaultMatcher {
	return &DefaultMatcher{}
}

func (m *DefaultMatcher) Match(conn *transport.ClientConnection) bool {
	return true
}
