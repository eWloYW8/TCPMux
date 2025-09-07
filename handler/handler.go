package handler

import (
	"fmt"

	"github.com/eWloYW8/TCPMux/transport"
	"gopkg.in/yaml.v3"
)

type Handler interface {
	Handle(conn *transport.ClientConnection)
}

type HandlerFactory func(yaml.Node) (Handler, error)

var handlerRegistry = make(map[string]HandlerFactory)

func Register(name string, factory HandlerFactory) {
	if _, exists := handlerRegistry[name]; exists {
		panic(fmt.Sprintf("handler '%s' already registered", name))
	}
	handlerRegistry[name] = factory
}

func NewHandler(handlerType string, parameter yaml.Node) (Handler, error) {
	factory, ok := handlerRegistry[handlerType]
	if !ok {
		return nil, fmt.Errorf("unknown handler type: %s", handlerType)
	}
	return factory(parameter)
}
