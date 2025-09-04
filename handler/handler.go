package handler

import (
	"fmt"
	"net"

	"github.com/eWloYW8/TCPMux/config"
)

type Handler interface {
	Handle(conn net.Conn)
}

type HandlerFactory func(*config.HandlerConfig) (Handler, error)

var handlerRegistry = make(map[string]HandlerFactory)

func Register(name string, factory HandlerFactory) {
	if _, exists := handlerRegistry[name]; exists {
		panic(fmt.Sprintf("handler '%s' already registered", name))
	}
	handlerRegistry[name] = factory
}

func NewHandler(handlerType string, cfg *config.HandlerConfig) (Handler, error) {
	factory, ok := handlerRegistry[handlerType]
	if !ok {
		return nil, fmt.Errorf("unknown handler type: %s", handlerType)
	}
	return factory(cfg)
}
