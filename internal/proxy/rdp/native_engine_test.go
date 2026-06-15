package rdpproxy

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tursom/turjmp/internal/config"
)

func TestRenderFreeRDPProxyConfigIncludesFixedTargetAndCertificates(t *testing.T) {
	cfg := nativeEngineTestConfig(t)
	raw := renderFreeRDPProxyFixedTargetConfig(cfg)
	for _, want := range []string{
		"[Server]",
		"Host=127.0.0.1",
		"Port=33900",
		"[Target]",
		"FixedTarget=true",
		"Host=win.internal",
		"Port=3389",
		"User=administrator",
		"Password=target-password",
		"[Security]",
		"ServerTlsSecurity=true",
		"ServerRdpSecurity=true",
		"ClientNlaSecurity=true",
		"[Certificates]",
		"CertificateFile=/tmp/rdp.crt",
		"PrivateKeyFile=/tmp/rdp.key",
	} {
		if !strings.Contains(raw, want) {
			t.Fatalf("config missing %q:\n%s", want, raw)
		}
	}
}

func TestRenderFreeRDPProxyConfigUsesTurjmpPluginWithoutTargetSecrets(t *testing.T) {
	cfg := nativeEngineTestConfig(t)
	cfg.APIBaseURL = "http://127.0.0.1:8080/"
	cfg.ProxyAuthSecret = "proxy-secret"
	cfg.MaxConnections = 12
	cfg.IdleTimeout = 30 * time.Second
	raw := renderFreeRDPProxyConfig(cfg)
	for _, want := range []string{
		"[Server]",
		"Host=127.0.0.1",
		"Port=33900",
		"[Target]",
		"FixedTarget=false",
		"[Plugins]",
		"Modules=turjmp",
		"Required=turjmp",
		"[Turjmp]",
		"APIBaseURL=http://127.0.0.1:8080",
		"ProxyAuth=proxy-secret",
		"MaxConnections=12",
		"IdleTimeoutSeconds=30",
		"[Certificates]",
		"CertificateFile=/tmp/rdp.crt",
		"PrivateKeyFile=/tmp/rdp.key",
	} {
		if !strings.Contains(raw, want) {
			t.Fatalf("config missing %q:\n%s", want, raw)
		}
	}
	for _, forbidden := range []string{"target-password", "User=administrator", "Password=target-password", "Host=win.internal"} {
		if strings.Contains(raw, forbidden) {
			t.Fatalf("dynamic config leaked %q:\n%s", forbidden, raw)
		}
	}
}

func TestNativeEngineRedaction(t *testing.T) {
	cfg := nativeEngineTestConfig(t)
	cfg.ProxyAuthSecret = "proxy-secret"
	redacted := cfg.Redacted()
	if redacted.Target.Password != "[redacted]" {
		t.Fatalf("password was not redacted: %#v", redacted.Target)
	}
	if redacted.ProxyAuthSecret != "[redacted]" {
		t.Fatalf("proxy auth secret was not redacted: %#v", redacted)
	}
	if strings.Contains((&NativeEngineError{
		Kind: NativeEngineErrorConfig,
		Op:   "target password",
		Err:  errors.New("password is required"),
	}).Error(), "target-password") {
		t.Fatal("error leaked password")
	}
	line := redactNativeEngineLogLine("TargetPassword=target-password Password: secret PrivateKeyContent=abc")
	for _, forbidden := range []string{"target-password", "secret", "abc"} {
		if strings.Contains(line, forbidden) {
			t.Fatalf("redacted line leaked %q: %q", forbidden, line)
		}
	}
}

func TestValidateNativeEngineConfigSkipsWhenDisabled(t *testing.T) {
	cfg := config.Config{
		Proxy: config.ProxyConfig{
			RDP: config.RDPProxyConfig{
				NativeEnabled:  true,
				NativeCertPath: "/missing/cert",
				NativeKeyPath:  "/missing/key",
			},
		},
	}
	cfg.Proxy.RDP.NativeEnabled = false
	if err := ValidateNativeEngineConfig(cfg); err != nil {
		t.Fatalf("disabled native engine should not validate dependencies: %v", err)
	}
}

func TestValidateNativeEngineConfigFailsFastWhenEnabled(t *testing.T) {
	cfg := config.Config{
		Proxy: config.ProxyConfig{
			RDP: config.RDPProxyConfig{
				NativeEnabled:    true,
				NativeEnginePath: filepath.Join(t.TempDir(), "missing-freerdp-proxy"),
				NativeCertPath:   "/missing/cert",
				NativeKeyPath:    "/missing/key",
				NativeWorkDir:    t.TempDir(),
			},
		},
	}
	err := ValidateNativeEngineConfig(cfg)
	var engineErr *NativeEngineError
	if !errors.As(err, &engineErr) {
		t.Fatalf("err=%T %v, want NativeEngineError", err, err)
	}
	if engineErr.Kind != NativeEngineErrorMissing || engineErr.Op != "engine" {
		t.Fatalf("kind/op=%s/%s", engineErr.Kind, engineErr.Op)
	}
}

func TestValidateNativeEngineConfigChecksCertificateAndKey(t *testing.T) {
	dir := t.TempDir()
	enginePath := filepath.Join(dir, "freerdp-proxy")
	if err := os.WriteFile(enginePath, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	certPath := filepath.Join(dir, "server.crt")
	keyPath := filepath.Join(dir, "server.key")
	if err := os.WriteFile(certPath, []byte("cert"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keyPath, []byte("key"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{
		Proxy: config.ProxyConfig{
			RDP: config.RDPProxyConfig{
				NativeEnabled:    true,
				NativeEnginePath: enginePath,
				NativeCertPath:   certPath,
				NativeKeyPath:    keyPath,
				NativeWorkDir:    filepath.Join(dir, "work"),
			},
		},
	}
	if err := ValidateNativeEngineConfig(cfg); err != nil {
		t.Fatalf("valid native engine config rejected: %v", err)
	}

	cfg.Proxy.RDP.NativeKeyPath = filepath.Join(dir, "missing.key")
	err := ValidateNativeEngineConfig(cfg)
	var engineErr *NativeEngineError
	if !errors.As(err, &engineErr) || engineErr.Op != "private key" {
		t.Fatalf("err=%T %v, want private key NativeEngineError", err, err)
	}
}

func TestFreeRDPEngineProcessLifecycle(t *testing.T) {
	dir := t.TempDir()
	enginePath := filepath.Join(dir, "fake-freerdp-proxy")
	if err := os.WriteFile(enginePath, []byte(`#!/bin/sh
echo "client authenticated"
echo "target connect failed: connection refused"
exec sleep 5
`), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()

	cfg := nativeEngineTestConfig(t)
	cfg.EnginePath = enginePath
	cfg.WorkDir = filepath.Join(dir, "work")
	engine := NewFreeRDPEngine()
	handle, err := engine.Start(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	events := collectNativeEventsUntil(t, handle.Events(), NativeEngineEventTargetDialFailed)
	if !hasNativeEvent(events, NativeEngineEventStarted) {
		t.Fatalf("missing started event: %#v", events)
	}
	if !hasNativeEvent(events, NativeEngineEventAuthenticated) {
		t.Fatalf("missing authenticated event: %#v", events)
	}
	if !hasNativeEvent(events, NativeEngineEventTargetDialFailed) {
		t.Fatalf("missing target dial event: %#v", events)
	}
	if err := handle.Stop(); err != nil {
		t.Fatalf("stop failed: %v", err)
	}
	if err := handle.Stop(); err != nil {
		t.Fatalf("second stop failed: %v", err)
	}
	err = handle.Wait()
	var engineErr *NativeEngineError
	if !errors.As(err, &engineErr) || engineErr.Kind != NativeEngineErrorExit {
		t.Fatalf("wait err=%T %v, want exit NativeEngineError", err, err)
	}
}

func TestFreeRDPEngineFastExitIsStartError(t *testing.T) {
	dir := t.TempDir()
	enginePath := filepath.Join(dir, "fake-freerdp-proxy")
	if err := os.WriteFile(enginePath, []byte("#!/bin/sh\nexit 42\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg := nativeEngineTestConfig(t)
	cfg.EnginePath = enginePath
	cfg.WorkDir = filepath.Join(dir, "work")
	_, err := NewFreeRDPEngine().Start(t.Context(), cfg)
	var engineErr *NativeEngineError
	if !errors.As(err, &engineErr) || engineErr.Kind != NativeEngineErrorStart {
		t.Fatalf("err=%T %v, want start NativeEngineError", err, err)
	}
}

func TestFreeRDPEngineContextCancelClassifiesWait(t *testing.T) {
	dir := t.TempDir()
	enginePath := filepath.Join(dir, "fake-freerdp-proxy")
	if err := os.WriteFile(enginePath, []byte("#!/bin/sh\nexec sleep 5\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	cfg := nativeEngineTestConfig(t)
	cfg.EnginePath = enginePath
	cfg.WorkDir = filepath.Join(dir, "work")
	handle, err := NewFreeRDPEngine().Start(ctx, cfg)
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	err = handle.Wait()
	var engineErr *NativeEngineError
	if !errors.As(err, &engineErr) || engineErr.Kind != NativeEngineErrorCanceled {
		t.Fatalf("wait err=%T %v, want canceled NativeEngineError", err, err)
	}
}

func TestClassifyNativeEngineEvents(t *testing.T) {
	tests := []struct {
		line string
		want NativeEngineEventType
	}{
		{line: "NLA authentication succeeded", want: NativeEngineEventAuthenticated},
		{line: "target connect failed: no route to host", want: NativeEngineEventTargetDialFailed},
		{line: "target login failed: access denied", want: NativeEngineEventTargetLoginFailed},
		{line: "client disconnected", want: NativeEngineEventDisconnected},
		{line: "ordinary FreeRDP proxy log", want: NativeEngineEventDebug},
	}
	for _, tt := range tests {
		t.Run(string(tt.want)+"-"+tt.line, func(t *testing.T) {
			event := classifyNativeEngineEvent("stderr", tt.line)
			if event.Type != tt.want {
				t.Fatalf("type=%s want %s", event.Type, tt.want)
			}
		})
	}
}

func TestNativeEngineConfigFromAppConfig(t *testing.T) {
	cfg := config.Config{
		ProxyAuth: config.ProxyAuthConfig{Secret: "proxy-secret"},
		Proxy: config.ProxyConfig{
			APIBaseURL: "http://127.0.0.1:8080",
			RDP: config.RDPProxyConfig{
				NativeAddr:       ":33900",
				NativeEnginePath: "/usr/bin/freerdp-proxy",
				NativeWorkDir:    "/tmp/turjmp-rdp-native",
				NativeCertPath:   "/cert.pem",
				NativeKeyPath:    "/key.pem",
			},
		},
	}
	engineCfg, err := NativeEngineConfigFromAppConfig(cfg, NativeFixedTarget{
		Host:     "win.internal",
		Username: "administrator",
		Password: "target-password",
	})
	if err != nil {
		t.Fatal(err)
	}
	if engineCfg.ListenHost != "0.0.0.0" || engineCfg.ListenPort != 33900 {
		t.Fatalf("listen=%s:%d", engineCfg.ListenHost, engineCfg.ListenPort)
	}
	if engineCfg.Target.Port != 3389 {
		t.Fatalf("target port=%d", engineCfg.Target.Port)
	}
	if engineCfg.APIBaseURL != "http://127.0.0.1:8080" || engineCfg.ProxyAuthSecret != "proxy-secret" || engineCfg.RequiredPluginName != "turjmp" {
		t.Fatalf("unexpected plugin fields: %#v", engineCfg.Redacted())
	}
}

func TestNativeEngineConfigFromResolvedAuth(t *testing.T) {
	cfg := config.Config{
		ProxyAuth: config.ProxyAuthConfig{Secret: "proxy-secret"},
		Proxy: config.ProxyConfig{
			APIBaseURL: "http://127.0.0.1:8080",
			RDP: config.RDPProxyConfig{
				NativeAddr:       "127.0.0.1:33900",
				NativeEnginePath: "/usr/bin/freerdp-proxy",
				NativeWorkDir:    "/tmp/turjmp-rdp-native",
				NativeCertPath:   "/cert.pem",
				NativeKeyPath:    "/key.pem",
			},
		},
	}
	engineCfg, err := NativeEngineConfigFromResolvedAuth(cfg, authResult{
		Target:  targetConfig{Address: "win.internal", Port: 3391, Protocol: "rdp"},
		Account: targetAccount{Username: "administrator", Secret: "target-password", SecretType: "password"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if engineCfg.ListenHost != "127.0.0.1" || engineCfg.ListenPort != 33900 {
		t.Fatalf("listen=%s:%d", engineCfg.ListenHost, engineCfg.ListenPort)
	}
	if engineCfg.Target.Host != "win.internal" || engineCfg.Target.Port != 3391 || engineCfg.Target.Username != "administrator" || engineCfg.Target.Password != "target-password" {
		t.Fatalf("unexpected target: %#v", engineCfg.Target)
	}
	if _, err := NativeEngineConfigFromResolvedAuth(cfg, authResult{
		Target:  targetConfig{Address: "win.internal", Protocol: "ssh"},
		Account: targetAccount{Username: "administrator", Secret: "target-password"},
	}); err == nil {
		t.Fatal("expected non-rdp auth to be rejected")
	}
}

func nativeEngineTestConfig(t *testing.T) NativeEngineConfig {
	t.Helper()
	return NativeEngineConfig{
		EnginePath:      "freerdp-proxy",
		WorkDir:         t.TempDir(),
		ListenHost:      "127.0.0.1",
		ListenPort:      33900,
		CertPath:        "/tmp/rdp.crt",
		KeyPath:         "/tmp/rdp.key",
		APIBaseURL:      "http://127.0.0.1:8080",
		ProxyAuthSecret: "proxy-secret",
		MaxConnections:  20,
		IdleTimeout:     time.Hour,
		Target: NativeFixedTarget{
			Host:     "win.internal",
			Port:     3389,
			Username: "administrator",
			Password: "target-password",
		},
	}
}

func collectNativeEventsUntil(t *testing.T, events <-chan NativeEngineEvent, want NativeEngineEventType) []NativeEngineEvent {
	t.Helper()
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	var out []NativeEngineEvent
	for {
		select {
		case event, ok := <-events:
			if !ok {
				return out
			}
			out = append(out, event)
			if event.Type == want {
				return out
			}
		case <-timer.C:
			t.Fatalf("timed out waiting for %s; events=%#v", want, out)
		}
	}
}

func hasNativeEvent(events []NativeEngineEvent, eventType NativeEngineEventType) bool {
	for _, event := range events {
		if event.Type == eventType {
			return true
		}
	}
	return false
}
