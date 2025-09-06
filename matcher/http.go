package matcher

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"

	"github.com/dlclark/regexp2"
	"github.com/eWloYW8/TCPMux/transport"
	"go.uber.org/zap"
	"gopkg.in/yaml.v3"
)

type HTTPMatcherConfig struct {
	Methods    []string `yaml:"methods"`
	URLSchemes []string `yaml:"url_schemes"`
	URLHosts   []string `yaml:"url_hosts"`
	URLPaths   []string `yaml:"url_paths"`
	Hosts      []string `yaml:"hosts"`
}

type HTTPMatcher struct {
	config       *HTTPMatcherConfig
	methodStrs   []string
	urlSchemeRes []*regexp2.Regexp
	urlHostRes   []*regexp2.Regexp
	urlPathRes   []*regexp2.Regexp
	hostRes      []*regexp2.Regexp
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

	for _, pattern := range cfg.URLSchemes {
		pattern = strings.ReplaceAll(pattern, "*", ".*")
		re, err := regexp2.Compile("^"+pattern+"$", regexp2.IgnoreCase)
		if err != nil {
			return nil, fmt.Errorf("invalid URLScheme pattern '%s': %v", pattern, err)
		}
		m.urlSchemeRes = append(m.urlSchemeRes, re)
	}

	for _, pattern := range cfg.URLHosts {
		pattern = strings.ReplaceAll(pattern, "*", ".*")
		re, err := regexp2.Compile("^"+pattern+"$", regexp2.IgnoreCase)
		if err != nil {
			return nil, fmt.Errorf("invalid URLHost pattern '%s': %v", pattern, err)
		}
		m.urlHostRes = append(m.urlHostRes, re)
	}

	for _, pattern := range cfg.URLPaths {
		pattern = strings.ReplaceAll(pattern, "*", ".*")
		re, err := regexp2.Compile("^"+pattern+"$", regexp2.IgnoreCase)
		if err != nil {
			return nil, fmt.Errorf("invalid URLPath pattern '%s': %v", pattern, err)
		}
		m.urlPathRes = append(m.urlPathRes, re)
	}

	for _, pattern := range cfg.Hosts {
		pattern = strings.ReplaceAll(pattern, "*", ".*")
		re, err := regexp2.Compile("^"+pattern+"$", regexp2.IgnoreCase)
		if err != nil {
			return nil, fmt.Errorf("invalid Host header pattern '%s': %v", pattern, err)
		}
		m.hostRes = append(m.hostRes, re)
	}

	return m, nil
}

func NewHTTPMatcher(cfg *HTTPMatcherConfig) *HTTPMatcher {
	m := &HTTPMatcher{config: cfg}
	for _, pattern := range cfg.URLSchemes {
		pattern = strings.ReplaceAll(pattern, "*", ".*")
		if re, err := regexp2.Compile("^"+pattern+"$", regexp2.IgnoreCase); err == nil {
			m.urlSchemeRes = append(m.urlSchemeRes, re)
		}
	}
	for _, pattern := range cfg.URLHosts {
		pattern = strings.ReplaceAll(pattern, "*", ".*")
		if re, err := regexp2.Compile("^"+pattern+"$", regexp2.IgnoreCase); err == nil {
			m.urlHostRes = append(m.urlHostRes, re)
		}
	}
	for _, pattern := range cfg.URLPaths {
		pattern = strings.ReplaceAll(pattern, "*", ".*")
		if re, err := regexp2.Compile("^"+pattern+"$", regexp2.IgnoreCase); err == nil {
			m.urlPathRes = append(m.urlPathRes, re)
		}
	}
	for _, pattern := range cfg.Hosts {
		pattern = strings.ReplaceAll(pattern, "*", ".*")
		if re, err := regexp2.Compile("^"+pattern+"$", regexp2.IgnoreCase); err == nil {
			m.hostRes = append(m.hostRes, re)
		}
	}
	return m
}

func (m *HTTPMatcher) Match(conn *transport.BufferedConn) bool {
	data := make([]byte, 8192)
	_, err := conn.ReadUnconsumed(data)
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(data)))
	if err != nil {
		if err != io.EOF {
			zap.L().Debug("Failed to parse HTTP request", zap.Error(err))
		}
		return false
	}
	defer req.Body.Close()

	// Match Method
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

	// Match URL Scheme
	if len(m.urlSchemeRes) > 0 {
		var schemeMatch bool
		for _, re := range m.urlSchemeRes {
			match, err := re.MatchString(req.URL.Scheme)
			if err != nil {
				zap.L().Error("regexp2 URLScheme match error", zap.Error(err))
				continue
			}
			if match {
				schemeMatch = true
				break
			}
		}
		if !schemeMatch {
			zap.L().Debug("HTTP URLScheme mismatch",
				zap.Strings("expected_patterns", m.config.URLSchemes),
				zap.String("received", req.URL.Scheme))
			return false
		}
	}

	// Match URL Host
	if len(m.urlHostRes) > 0 {
		var urlHostMatch bool
		for _, re := range m.urlHostRes {
			match, err := re.MatchString(req.URL.Host)
			if err != nil {
				zap.L().Error("regexp2 URLHost match error", zap.Error(err))
				continue
			}
			if match {
				urlHostMatch = true
				break
			}
		}
		if !urlHostMatch {
			zap.L().Debug("HTTP URLHost mismatch",
				zap.Strings("expected_patterns", m.config.URLHosts),
				zap.String("received", req.URL.Host))
			return false
		}
	}

	// Match URL Path
	if len(m.urlPathRes) > 0 {
		var urlPathMatch bool
		for _, re := range m.urlPathRes {
			match, err := re.MatchString(req.URL.Path)
			if err != nil {
				zap.L().Error("regexp2 URLPath match error", zap.Error(err))
				continue
			}
			if match {
				urlPathMatch = true
				break
			}
		}
		if !urlPathMatch {
			zap.L().Debug("HTTP URLPath mismatch",
				zap.Strings("expected_patterns", m.config.URLPaths),
				zap.String("received", req.URL.Path))
			return false
		}
	}

	// Match Host header
	if len(m.hostRes) > 0 {
		var hostMatch bool
		for _, re := range m.hostRes {
			match, err := re.MatchString(req.Host)
			if err != nil {
				zap.L().Error("regexp2 Host header match error", zap.Error(err))
				continue
			}
			if match {
				hostMatch = true
				break
			}
		}
		if !hostMatch {
			zap.L().Debug("HTTP Host header mismatch",
				zap.Strings("expected_patterns", m.config.Hosts),
				zap.String("received", req.Host))
			return false
		}
	}

	return true
}
