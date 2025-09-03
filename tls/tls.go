package tls

import (
	"crypto/tls"
	"fmt"

	"github.com/eWloYW8/TCPMux/config"
	"go.uber.org/zap"
)

func NewTLSConfig(cfg *config.TLSConfig) (*tls.Config, error) {
	if !cfg.Enabled {
		return nil, nil
	}

	certificates := make(map[string]*tls.Certificate)
	var defaultCert *tls.Certificate

	for _, sniCfg := range cfg.Config {
		cert, err := tls.LoadX509KeyPair(sniCfg.Cert, sniCfg.Key)
		if err != nil {
			return nil, fmt.Errorf("failed to load key pair for SNI %s: %v", sniCfg.SNI, err)
		}

		if sniCfg.SNI == "*" {
			defaultCert = &cert
		} else {
			certificates[sniCfg.SNI] = &cert
		}
		zap.L().Info("Successfully loaded TLS certificate", zap.String("sni", sniCfg.SNI))
	}

	tlsConfig := &tls.Config{
		Certificates: nil,
		GetCertificate: func(hello *tls.ClientHelloInfo) (*tls.Certificate, error) {
			if cert, ok := certificates[hello.ServerName]; ok {
				return cert, nil
			}

			if defaultCert != nil {
				return defaultCert, nil
			}
			zap.L().Warn("No certificate found for SNI", zap.String("sni", hello.ServerName))
			return nil, fmt.Errorf("no certificate found for SNI: %s", hello.ServerName)
		},
	}

	return tlsConfig, nil
}
