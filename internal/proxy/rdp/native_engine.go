package rdpproxy

import (
	"bufio"
	"context"
	"errors"
	"io"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/tursom/turjmp/internal/config"
)

// NativeEngineEventType describes lifecycle signals emitted by the native RDP MITM engine.
type NativeEngineEventType string

const (
	NativeEngineEventStarted           NativeEngineEventType = "started"
	NativeEngineEventAuthenticated     NativeEngineEventType = "authenticated"
	NativeEngineEventTargetDialFailed  NativeEngineEventType = "target_dial_failed"
	NativeEngineEventTargetLoginFailed NativeEngineEventType = "target_login_failed"
	NativeEngineEventDisconnected      NativeEngineEventType = "disconnected"
	NativeEngineEventProcessExited     NativeEngineEventType = "process_exited"
	NativeEngineEventDebug             NativeEngineEventType = "debug"
)

// NativeEngineErrorKind classifies startup and process failures without embedding secrets.
type NativeEngineErrorKind string

const (
	NativeEngineErrorConfig   NativeEngineErrorKind = "config"
	NativeEngineErrorMissing  NativeEngineErrorKind = "missing"
	NativeEngineErrorStart    NativeEngineErrorKind = "start"
	NativeEngineErrorExit     NativeEngineErrorKind = "exit"
	NativeEngineErrorCanceled NativeEngineErrorKind = "canceled"
)

// NativeEngineError is a redacted error suitable for logs and API surfaces.
type NativeEngineError struct {
	Kind NativeEngineErrorKind
	Op   string
	Path string
	Err  error
}

func (e *NativeEngineError) Error() string {
	parts := []string{"native rdp engine"}
	if e.Op != "" {
		parts = append(parts, e.Op)
	}
	if e.Kind != "" {
		parts = append(parts, string(e.Kind))
	}
	if e.Path != "" {
		parts = append(parts, e.Path)
	}
	if e.Err != nil {
		parts = append(parts, e.Err.Error())
	}
	return strings.Join(parts, ": ")
}

func (e *NativeEngineError) Unwrap() error {
	return e.Err
}

// NativeEngineEvent is a structured, redacted event produced from FreeRDP stdout/stderr.
type NativeEngineEvent struct {
	Type   NativeEngineEventType
	Source string
	Line   string
	Time   time.Time
	Code   int
}

// NativeFixedTarget describes the fixed target used by the F3R.2 PoC wrapper.
type NativeFixedTarget struct {
	Host     string
	Port     int
	Username string
	Password string
}

// NativeEngineConfig is the complete process boundary for the FreeRDP CLI wrapper.
type NativeEngineConfig struct {
	EnginePath         string
	WorkDir            string
	ListenHost         string
	ListenPort         int
	CertPath           string
	KeyPath            string
	Target             NativeFixedTarget
	APIBaseURL         string
	ProxyAuthSecret    string
	PluginName         string
	RequiredPluginName string
	MaxConnections     int
	IdleTimeout        time.Duration
}

// Redacted returns a copy with secret material removed.
func (c NativeEngineConfig) Redacted() NativeEngineConfig {
	out := c
	out.Target.Password = "[redacted]"
	if out.ProxyAuthSecret != "" {
		out.ProxyAuthSecret = "[redacted]"
	}
	return out
}

// NativeEngineHandle controls a running native RDP MITM engine process.
type NativeEngineHandle struct {
	cmd      *exec.Cmd
	events   chan NativeEngineEvent
	done     chan error
	stopOnce sync.Once
}

// Events returns a redacted stream of parsed engine events.
func (h *NativeEngineHandle) Events() <-chan NativeEngineEvent {
	return h.events
}

// Wait waits for the engine process to exit.
func (h *NativeEngineHandle) Wait() error {
	return <-h.done
}

// Stop terminates the engine process. It is safe to call multiple times.
func (h *NativeEngineHandle) Stop() error {
	var err error
	h.stopOnce.Do(func() {
		if h.cmd == nil || h.cmd.Process == nil {
			return
		}
		err = h.cmd.Process.Kill()
		if errors.Is(err, os.ErrProcessDone) {
			err = nil
		}
	})
	return err
}

// FreeRDPEngine wraps the freerdp-proxy CLI.
type FreeRDPEngine struct {
	runner nativeCommandRunner
}

type nativeCommandRunner interface {
	CommandContext(ctx context.Context, name string, args ...string) nativeCommand
}

type nativeCommand interface {
	StdoutPipe() (io.ReadCloser, error)
	StderrPipe() (io.ReadCloser, error)
	Start() error
	Wait() error
	Process() *os.Process
}

type osCommandRunner struct{}

func (osCommandRunner) CommandContext(ctx context.Context, name string, args ...string) nativeCommand {
	return &execNativeCommand{cmd: exec.CommandContext(ctx, name, args...)}
}

type execNativeCommand struct {
	cmd *exec.Cmd
}

func (c *execNativeCommand) StdoutPipe() (io.ReadCloser, error) { return c.cmd.StdoutPipe() }
func (c *execNativeCommand) StderrPipe() (io.ReadCloser, error) { return c.cmd.StderrPipe() }
func (c *execNativeCommand) Start() error                       { return c.cmd.Start() }
func (c *execNativeCommand) Wait() error                        { return c.cmd.Wait() }
func (c *execNativeCommand) Process() *os.Process               { return c.cmd.Process }

// NewFreeRDPEngine creates a FreeRDP CLI wrapper.
func NewFreeRDPEngine() *FreeRDPEngine {
	return &FreeRDPEngine{runner: osCommandRunner{}}
}

// NativeEngineConfigFromAppConfig converts Turjmp config plus a fixed target into wrapper config.
func NativeEngineConfigFromAppConfig(cfg config.Config, target NativeFixedTarget) (NativeEngineConfig, error) {
	host, port, err := splitNativeListenAddr(cfg.Proxy.RDP.NativeListenAddr())
	if err != nil {
		return NativeEngineConfig{}, err
	}
	if target.Port <= 0 {
		target.Port = 3389
	}
	return NativeEngineConfig{
		EnginePath:         cfg.Proxy.RDP.NativeEngineCommand(),
		WorkDir:            cfg.Proxy.RDP.NativeEngineWorkDir(),
		ListenHost:         host,
		ListenPort:         port,
		CertPath:           cfg.Proxy.RDP.NativeCertPath,
		KeyPath:            cfg.Proxy.RDP.NativeKeyPath,
		Target:             target,
		APIBaseURL:         strings.TrimRight(cfg.Proxy.APIBaseURL, "/"),
		ProxyAuthSecret:    cfg.ProxyAuth.Secret,
		PluginName:         "turjmp",
		RequiredPluginName: "turjmp",
		MaxConnections:     cfg.Proxy.RDP.ConnectionLimit(),
		IdleTimeout:        cfg.Proxy.RDP.IdleTimeout(),
	}, nil
}

// NativeEngineConfigFromResolvedAuth converts a Turjmp-native RDP resolution into engine config.
func NativeEngineConfigFromResolvedAuth(cfg config.Config, auth authResult) (NativeEngineConfig, error) {
	if err := validateRDPAuth(auth); err != nil {
		return NativeEngineConfig{}, err
	}
	return NativeEngineConfigFromAppConfig(cfg, NativeFixedTarget{
		Host:     auth.Target.Address,
		Port:     rdpTargetPort(auth.Target),
		Username: auth.Account.Username,
		Password: auth.Account.Secret,
	})
}

// ValidateNativeEngineConfig performs fail-fast checks only when native RDP is enabled.
func ValidateNativeEngineConfig(cfg config.Config) error {
	if !cfg.Proxy.RDP.NativeEnabled {
		return nil
	}
	if _, err := exec.LookPath(cfg.Proxy.RDP.NativeEngineCommand()); err != nil {
		return &NativeEngineError{Kind: NativeEngineErrorMissing, Op: "engine", Path: cfg.Proxy.RDP.NativeEngineCommand(), Err: err}
	}
	if err := requireReadableFile("certificate", cfg.Proxy.RDP.NativeCertPath); err != nil {
		return err
	}
	if err := requireReadableFile("private key", cfg.Proxy.RDP.NativeKeyPath); err != nil {
		return err
	}
	if err := os.MkdirAll(cfg.Proxy.RDP.NativeEngineWorkDir(), 0o700); err != nil {
		return &NativeEngineError{Kind: NativeEngineErrorConfig, Op: "work dir", Path: cfg.Proxy.RDP.NativeEngineWorkDir(), Err: err}
	}
	return nil
}

func requireReadableFile(op, path string) error {
	if strings.TrimSpace(path) == "" {
		return &NativeEngineError{Kind: NativeEngineErrorMissing, Op: op, Err: errors.New("path is required")}
	}
	file, err := os.Open(path)
	if err != nil {
		return &NativeEngineError{Kind: NativeEngineErrorMissing, Op: op, Path: path, Err: err}
	}
	return file.Close()
}

// Start renders a FreeRDP config file and starts freerdp-proxy with that file as the only argument.
func (e *FreeRDPEngine) Start(ctx context.Context, cfg NativeEngineConfig) (*NativeEngineHandle, error) {
	if e.runner == nil {
		e.runner = osCommandRunner{}
	}
	if err := validateNativeEngineRuntimeConfig(cfg); err != nil {
		return nil, err
	}
	if err := os.MkdirAll(cfg.WorkDir, 0o700); err != nil {
		return nil, &NativeEngineError{Kind: NativeEngineErrorConfig, Op: "work dir", Path: cfg.WorkDir, Err: err}
	}
	configPath := filepath.Join(cfg.WorkDir, "freerdp-proxy.ini")
	if err := os.WriteFile(configPath, []byte(renderFreeRDPProxyConfig(cfg)), 0o600); err != nil {
		return nil, &NativeEngineError{Kind: NativeEngineErrorConfig, Op: "render config", Path: configPath, Err: err}
	}

	cmd := e.runner.CommandContext(ctx, cfg.EnginePath, configPath)
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return nil, &NativeEngineError{Kind: NativeEngineErrorStart, Op: "stdout pipe", Err: err}
	}
	stderr, err := cmd.StderrPipe()
	if err != nil {
		return nil, &NativeEngineError{Kind: NativeEngineErrorStart, Op: "stderr pipe", Err: err}
	}
	if err := cmd.Start(); err != nil {
		return nil, &NativeEngineError{Kind: NativeEngineErrorStart, Op: "start", Path: cfg.EnginePath, Err: err}
	}

	events := make(chan NativeEngineEvent, 32)
	done := make(chan error, 1)
	handle := &NativeEngineHandle{
		cmd:    execCommandFromNative(cmd),
		events: events,
		done:   done,
	}
	events <- NativeEngineEvent{Type: NativeEngineEventStarted, Time: time.Now()}
	var scanWG sync.WaitGroup
	scanWG.Add(2)
	go func() {
		defer scanWG.Done()
		scanNativeEngineEvents(events, stdout, "stdout")
	}()
	go func() {
		defer scanWG.Done()
		scanNativeEngineEvents(events, stderr, "stderr")
	}()
	go func() {
		err := cmd.Wait()
		if ctx.Err() != nil {
			err = &NativeEngineError{Kind: NativeEngineErrorCanceled, Op: "wait", Err: ctx.Err()}
		} else if err != nil {
			err = &NativeEngineError{Kind: NativeEngineErrorExit, Op: "wait", Err: err}
		}
		scanWG.Wait()
		emitNativeEngineEvent(events, NativeEngineEvent{Type: NativeEngineEventProcessExited, Time: time.Now(), Code: nativeExitCode(err)})
		close(events)
		done <- err
	}()
	select {
	case err := <-done:
		if err == nil {
			err = errors.New("process exited during startup")
		}
		return nil, &NativeEngineError{Kind: NativeEngineErrorStart, Op: "start", Path: cfg.EnginePath, Err: err}
	case <-time.After(100 * time.Millisecond):
		return handle, nil
	}
}

func execCommandFromNative(cmd nativeCommand) *exec.Cmd {
	if wrapped, ok := cmd.(*execNativeCommand); ok {
		return wrapped.cmd
	}
	return &exec.Cmd{Process: cmd.Process()}
}

func validateNativeEngineRuntimeConfig(cfg NativeEngineConfig) error {
	if strings.TrimSpace(cfg.EnginePath) == "" {
		return &NativeEngineError{Kind: NativeEngineErrorConfig, Op: "engine", Err: errors.New("path is required")}
	}
	if strings.TrimSpace(cfg.WorkDir) == "" {
		return &NativeEngineError{Kind: NativeEngineErrorConfig, Op: "work dir", Err: errors.New("path is required")}
	}
	if strings.TrimSpace(cfg.ListenHost) == "" {
		return &NativeEngineError{Kind: NativeEngineErrorConfig, Op: "listen host", Err: errors.New("host is required")}
	}
	if cfg.ListenPort <= 0 || cfg.ListenPort > 65535 {
		return &NativeEngineError{Kind: NativeEngineErrorConfig, Op: "listen port", Err: errors.New("port is invalid")}
	}
	if strings.TrimSpace(cfg.CertPath) == "" {
		return &NativeEngineError{Kind: NativeEngineErrorConfig, Op: "certificate", Err: errors.New("path is required")}
	}
	if strings.TrimSpace(cfg.KeyPath) == "" {
		return &NativeEngineError{Kind: NativeEngineErrorConfig, Op: "private key", Err: errors.New("path is required")}
	}
	if strings.TrimSpace(cfg.APIBaseURL) == "" {
		return &NativeEngineError{Kind: NativeEngineErrorConfig, Op: "api base url", Err: errors.New("url is required")}
	}
	if strings.TrimSpace(cfg.ProxyAuthSecret) == "" {
		return &NativeEngineError{Kind: NativeEngineErrorConfig, Op: "proxy auth", Err: errors.New("secret is required")}
	}
	return nil
}

func renderFreeRDPProxyConfig(cfg NativeEngineConfig) string {
	return renderFreeRDPProxyDynamicConfig(cfg)
}

func renderFreeRDPProxyDynamicConfig(cfg NativeEngineConfig) string {
	var b strings.Builder
	pluginName := defaultString(cfg.PluginName, "turjmp")
	requiredPluginName := defaultString(cfg.RequiredPluginName, pluginName)
	writeINISection(&b, "Server")
	writeINIKey(&b, "Host", cfg.ListenHost)
	writeINIKey(&b, "Port", strconv.Itoa(cfg.ListenPort))
	b.WriteByte('\n')

	writeINISection(&b, "Target")
	writeINIKey(&b, "FixedTarget", "false")
	b.WriteByte('\n')

	writeINISection(&b, "Security")
	writeINIKey(&b, "ServerNlaSecurity", "false")
	writeINIKey(&b, "ServerTlsSecurity", "true")
	writeINIKey(&b, "ServerRdpSecurity", "true")
	writeINIKey(&b, "ClientNlaSecurity", "true")
	writeINIKey(&b, "ClientTlsSecurity", "true")
	writeINIKey(&b, "ClientRdpSecurity", "true")
	writeINIKey(&b, "ClientAllowFallbackToTls", "true")
	b.WriteByte('\n')

	writeINISection(&b, "Certificates")
	writeINIKey(&b, "CertificateFile", cfg.CertPath)
	writeINIKey(&b, "PrivateKeyFile", cfg.KeyPath)
	b.WriteByte('\n')

	writeINISection(&b, "Plugins")
	writeINIKey(&b, "Modules", pluginName)
	writeINIKey(&b, "Required", requiredPluginName)
	b.WriteByte('\n')

	writeINISection(&b, "Turjmp")
	writeINIKey(&b, "APIBaseURL", strings.TrimRight(cfg.APIBaseURL, "/"))
	writeINIKey(&b, "ProxyAuth", cfg.ProxyAuthSecret)
	writeINIKey(&b, "MaxConnections", strconv.Itoa(cfg.MaxConnections))
	writeINIKey(&b, "IdleTimeoutSeconds", strconv.Itoa(int(cfg.IdleTimeout.Seconds())))
	return b.String()
}

func renderFreeRDPProxyFixedTargetConfig(cfg NativeEngineConfig) string {
	var b strings.Builder
	writeINISection(&b, "Server")
	writeINIKey(&b, "Host", cfg.ListenHost)
	writeINIKey(&b, "Port", strconv.Itoa(cfg.ListenPort))
	b.WriteByte('\n')

	writeINISection(&b, "Target")
	writeINIKey(&b, "FixedTarget", "true")
	writeINIKey(&b, "Host", cfg.Target.Host)
	writeINIKey(&b, "Port", strconv.Itoa(cfg.Target.Port))
	writeINIKey(&b, "User", cfg.Target.Username)
	writeINIKey(&b, "Password", cfg.Target.Password)
	b.WriteByte('\n')

	writeINISection(&b, "Security")
	writeINIKey(&b, "ServerNlaSecurity", "false")
	writeINIKey(&b, "ServerTlsSecurity", "true")
	writeINIKey(&b, "ServerRdpSecurity", "true")
	writeINIKey(&b, "ClientNlaSecurity", "true")
	writeINIKey(&b, "ClientTlsSecurity", "true")
	writeINIKey(&b, "ClientRdpSecurity", "true")
	writeINIKey(&b, "ClientAllowFallbackToTls", "true")
	b.WriteByte('\n')

	writeINISection(&b, "Certificates")
	writeINIKey(&b, "CertificateFile", cfg.CertPath)
	writeINIKey(&b, "PrivateKeyFile", cfg.KeyPath)
	return b.String()
}

func writeINISection(b *strings.Builder, section string) {
	b.WriteString("[")
	b.WriteString(section)
	b.WriteString("]\n")
}

func writeINIKey(b *strings.Builder, key, value string) {
	b.WriteString(key)
	b.WriteString("=")
	b.WriteString(escapeINIValue(value))
	b.WriteByte('\n')
}

func escapeINIValue(value string) string {
	value = strings.ReplaceAll(value, "\r", "")
	value = strings.ReplaceAll(value, "\n", "")
	return value
}

func scanNativeEngineEvents(events chan<- NativeEngineEvent, r io.Reader, source string) {
	scanner := bufio.NewScanner(r)
	for scanner.Scan() {
		line := scanner.Text()
		emitNativeEngineEvent(events, classifyNativeEngineEvent(source, line))
	}
}

func emitNativeEngineEvent(events chan<- NativeEngineEvent, event NativeEngineEvent) {
	select {
	case events <- event:
	default:
	}
}

func classifyNativeEngineEvent(source, line string) NativeEngineEvent {
	normalized := strings.ToLower(line)
	eventType := NativeEngineEventDebug
	switch {
	case containsAny(normalized, "authenticat", "login successful", "nla succeeded"):
		eventType = NativeEngineEventAuthenticated
	case containsAny(normalized, "target") && containsAny(normalized, "connect failed", "connection refused", "no route to host", "timed out", "timeout", "unreachable"):
		eventType = NativeEngineEventTargetDialFailed
	case containsAny(normalized, "logon failure", "login failed", "authentication failed", "credentials", "access denied"):
		eventType = NativeEngineEventTargetLoginFailed
	case containsAny(normalized, "disconnect", "disconnected", "connection closed"):
		eventType = NativeEngineEventDisconnected
	}
	return NativeEngineEvent{Type: eventType, Source: source, Line: redactNativeEngineLogLine(line), Time: time.Now()}
}

func containsAny(value string, needles ...string) bool {
	for _, needle := range needles {
		if strings.Contains(value, needle) {
			return true
		}
	}
	return false
}

func redactNativeEngineLogLine(line string) string {
	fields := []string{"Password", "TargetPassword", "ProxyAuth", "PrivateKeyContent", "CertificateContent"}
	for _, field := range fields {
		line = redactKeyValue(line, field)
	}
	return line
}

func redactKeyValue(line, field string) string {
	for _, sep := range []string{"=", ": "} {
		prefix := field + sep
		idx := strings.Index(line, prefix)
		if idx < 0 {
			continue
		}
		start := idx + len(prefix)
		end := strings.IndexAny(line[start:], " \t,;")
		if end < 0 {
			return line[:start] + "[redacted]"
		}
		end += start
		line = line[:start] + "[redacted]" + line[end:]
	}
	return line
}

func splitNativeListenAddr(addr string) (string, int, error) {
	host, portRaw, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, &NativeEngineError{Kind: NativeEngineErrorConfig, Op: "listen addr", Path: addr, Err: err}
	}
	if host == "" {
		host = "0.0.0.0"
	}
	port, err := strconv.Atoi(portRaw)
	if err != nil || port <= 0 || port > 65535 {
		return "", 0, &NativeEngineError{Kind: NativeEngineErrorConfig, Op: "listen addr", Path: addr, Err: errors.New("port is invalid")}
	}
	return host, port, nil
}

func nativeExitCode(err error) int {
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		return exitErr.ExitCode()
	}
	if err == nil {
		return 0
	}
	return -1
}
