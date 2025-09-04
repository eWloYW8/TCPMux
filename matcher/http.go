package matcher

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"

	"github.com/dlclark/regexp2"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

type HTTPMatcherConfig struct {
	Methods []string `yaml:"methods"`
	Paths   []string `yaml:"paths"`
	Hosts   []string `yaml:"hosts"`
}

type HTTPMatcher struct {
	config  *HTTPMatcherConfig
	pathRes []*regexp2.Regexp
	hostRes []*regexp2.Regexp
}

func init() {
	Register("http", newHTTPMatcher)
}

func newHTTPMatcher(parameter yaml.Node) (Matcher, error) {
	cfg := &HTTPMatcherConfig{}
	if err := parameter.Decode(cfg); err != nil {
		return nil, fmt.Errorf("failed to decode http matcher config: %v", err)
	}

	m := &HTTPMatcher{config: cfg}

	for _, pathPattern := range cfg.Paths {
		pathPattern = strings.ReplaceAll(pathPattern, "*", ".*")
		re, err := regexp2.Compile("^"+pathPattern+"$", regexp2.IgnoreCase)
		if err != nil {
			return nil, fmt.Errorf("invalid path pattern '%s': %v", pathPattern, err)
		}
		m.pathRes = append(m.pathRes, re)
	}

	for _, hostPattern := range cfg.Hosts {
		hostPattern = strings.ReplaceAll(hostPattern, "*", ".*")
		re, err := regexp2.Compile("^"+hostPattern+"$", regexp2.IgnoreCase)
		if err != nil {
			return nil, fmt.Errorf("invalid host pattern '%s': %v", hostPattern, err)
		}
		m.hostRes = append(m.hostRes, re)
	}

	return m, nil
}

func NewHTTPMatcher(cfg *HTTPMatcherConfig) *HTTPMatcher {
	m := &HTTPMatcher{config: cfg}
	for _, pathPattern := range cfg.Paths {
		pathPattern = strings.ReplaceAll(pathPattern, "*", ".*")
		if re, err := regexp2.Compile("^"+pathPattern+"$", regexp2.IgnoreCase); err == nil {
			m.pathRes = append(m.pathRes, re)
		}
	}
	for _, hostPattern := range cfg.Hosts {
		hostPattern = strings.ReplaceAll(hostPattern, "*", ".*")
		if re, err := regexp2.Compile("^"+hostPattern+"$", regexp2.IgnoreCase); err == nil {
			m.hostRes = append(m.hostRes, re)
		}
	}
	return m
}

func (m *HTTPMatcher) Match(conn net.Conn, data []byte) bool {
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(data)))
	if err != nil {
		if err != io.EOF {
			zap.L().Debug("Failed to parse HTTP request", zap.Error(err))
		}
		return false
	}
	defer req.Body.Close()

	if len(m.config.Methods) > 0 {
		var methodMatch bool
		for _, method := range m.config.Methods {
			if strings.EqualFold(req.Method, method) {
				methodMatch = true
				break
			}
		}
		if !methodMatch {
			zap.L().Debug("HTTP method mismatch",
				zap.Strings("expected", m.config.Methods),
				zap.String("received", req.Method))
			return false
		}
	}

	if len(m.pathRes) > 0 {
		var pathMatch bool
		for _, re := range m.pathRes {
			match, err := re.MatchString(req.URL.Path)
			if err != nil {
				zap.L().Error("regexp2 path match error", zap.Error(err))
				continue
			}
			if match {
				pathMatch = true
				break
			}
		}
		if !pathMatch {
			zap.L().Debug("HTTP path mismatch",
				zap.Strings("expected_patterns", m.config.Paths),
				zap.String("received", req.URL.Path))
			return false
		}
	}

	host := req.Host
	if host == "" {
		host, _, _ = net.SplitHostPort(req.URL.Host)
	}

	if len(m.hostRes) > 0 {
		var hostMatch bool
		for _, re := range m.hostRes {
			match, err := re.MatchString(host)
			if err != nil {
				zap.L().Error("regexp2 host match error", zap.Error(err))
				continue
			}
			if match {
				hostMatch = true
				break
			}
		}
		if !hostMatch {
			zap.L().Debug("HTTP host mismatch",
				zap.Strings("expected_patterns", m.config.Hosts),
				zap.String("received", host))
			return false
		}
	}

	return true
}
