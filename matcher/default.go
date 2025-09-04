package matcher

import (
	"net"

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

func (m *DefaultMatcher) Match(conn net.Conn, data []byte) bool {
	return true
}
