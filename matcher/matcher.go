package matcher

import (
	"fmt"

	"github.com/eWloYW8/TCPMux/transport"
	"gopkg.in/yaml.v3"
)

type Matcher interface {
	Match(conn *transport.BufferedConn) bool
}

type MatcherFactory func(yaml.Node) (Matcher, error)

var matcherRegistry = make(map[string]MatcherFactory)

func Register(name string, factory MatcherFactory) {
	if _, exists := matcherRegistry[name]; exists {
		panic(fmt.Sprintf("matcher '%s' already registered", name))
	}
	matcherRegistry[name] = factory
}

func NewMatcher(ruleType string, parameter yaml.Node) (Matcher, error) {
	factory, ok := matcherRegistry[ruleType]
	if !ok {
		return nil, fmt.Errorf("unknown matcher type: %s", ruleType)
	}
	return factory(parameter)
}
