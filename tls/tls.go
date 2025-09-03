package tls

import (
	"crypto/tls"
	"fmt"

	"github.com/eWloYW8/TCPMux/config"
)

func NewTLSConfig(cfg *config.TLSConfig) (*tls.Config, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	tlsConfig := &tls.Config{
		Certificates: make([]tls.Certificate, 0, len(cfg.Config)),
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			for _, sniCfg := range cfg.Config {
				if sniCfg.SNI == "*" {
					continue
				}
				if hello.ServerName == sniCfg.SNI {
					cert, err := tls.LoadX509KeyPair(sniCfg.Cert, sniCfg.Key)
					if err != nil {
						return nil, err
					}
					return &cert, nil
				}
			}

			// Default cert
			for _, sniCfg := range cfg.Config {
				if sniCfg.SNI == "*" {
					cert, err := tls.LoadX509KeyPair(sniCfg.Cert, sniCfg.Key)
					if err != nil {
						return nil, err
					}
					return &cert, nil
				}
			}

			return nil, fmt.Errorf("no certificate found for SNI: %s", hello.ServerName)
		},
	}

	return tlsConfig, nil
}
