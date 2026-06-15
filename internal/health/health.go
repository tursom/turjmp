package health

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/tursom/turjmp/internal/config"
)

const (
	StatusReady    = "ready"
	StatusNotReady = "not_ready"
	StatusDisabled = "disabled"
)

type Component struct {
	Status string `json:"status"`
	Error  string `json:"error,omitempty"`
}

type Readiness struct {
	Status     string               `json:"status"`
	Components map[string]Component `json:"components"`
}

func NewReadiness(components map[string]Component) Readiness {
	status := StatusReady
	for _, component := range components {
		if component.Status == StatusNotReady {
			status = StatusNotReady
			break
		}
	}
	return Readiness{Status: status, Components: components}
}

func Ready() Component {
	return Component{Status: StatusReady}
}

func Disabled() Component {
	return Component{Status: StatusDisabled}
}

func NotReady(err error) Component {
	return Component{Status: StatusNotReady, Error: sanitizeError(err)}
}

func sanitizeError(err error) string {
	if err == nil {
		return ""
	}
	message := err.Error()
	for _, marker := range []string{"password", "secret", "proxyauth", "proxy auth", "private key content"} {
		if strings.Contains(strings.ToLower(message), marker) {
			return "redacted"
		}
	}
	return message
}

func ProbeRDPProxy(ctx context.Context, cfg config.Config) Component {
	ready := ProbeRDPProxyReadiness(ctx, cfg)
	if ready.Status != StatusReady {
		return Component{Status: StatusNotReady, Error: ready.Status}
	}
	return Ready()
}

func ProbeRDPProxyReadiness(ctx context.Context, cfg config.Config) Readiness {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, rdpProxyHealthURL(cfg), nil)
	if err != nil {
		return NewReadiness(map[string]Component{"web_rdp": NotReady(err)})
	}
	resp, err := (&http.Client{Timeout: cfg.Proxy.RDP.ConnectTimeout()}).Do(req)
	if err != nil {
		return NewReadiness(map[string]Component{"web_rdp": NotReady(err)})
	}
	defer resp.Body.Close()
	var ready Readiness
	if err := json.NewDecoder(resp.Body).Decode(&ready); err != nil {
		if resp.StatusCode != http.StatusOK {
			component := NotReady(statusError(resp.Status))
			return NewReadiness(map[string]Component{
				"web_rdp":    component,
				"native_rdp": component,
			})
		}
		return NewReadiness(map[string]Component{"web_rdp": NotReady(err)})
	}
	if ready.Components == nil {
		ready.Components = map[string]Component{}
	}
	if resp.StatusCode != http.StatusOK && ready.Status == StatusReady {
		ready.Status = StatusNotReady
	}
	return ready
}

func rdpProxyHealthURL(cfg config.Config) string {
	host, port, err := net.SplitHostPort(cfg.Proxy.RDP.ListenAddr())
	if err != nil || port == "" {
		port = "33891"
	}
	if host == "" || host == "0.0.0.0" || host == "::" || host == "[::]" {
		host = "127.0.0.1"
	}
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		host = "[" + host + "]"
	}
	return "http://" + host + ":" + port + "/health"
}

type statusError string

func (e statusError) Error() string {
	return string(e)
}

func WithTimeout(parent context.Context, timeout time.Duration) (context.Context, context.CancelFunc) {
	if timeout <= 0 {
		timeout = 2 * time.Second
	}
	return context.WithTimeout(parent, timeout)
}
