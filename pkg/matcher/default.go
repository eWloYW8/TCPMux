package matcher

import "net"

type DefaultMatcher struct{}

func NewDefaultMatcher() *DefaultMatcher {
	return &DefaultMatcher{}
}

func (m *DefaultMatcher) Match(conn net.Conn, data []byte) bool {
	return true
}
