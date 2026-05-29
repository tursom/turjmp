package rdpproxy

import (
	"context"
	"errors"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tursom/turjmp/internal/config"
)

type fakeAPI struct {
	auth         authResult
	verifyErr    error
	createErr    error
	finishErr    error
	finishedID   int64
	finishedPath string
}

func (f *fakeAPI) VerifyConnectionToken(_ context.Context, token, remoteAddr string) (authResult, error) {
	if f.verifyErr != nil {
		return authResult{}, f.verifyErr
	}
	return f.auth, nil
}

func (f *fakeAPI) CreateSession(_ context.Context, session sessionInfo) (sessionInfo, error) {
	if f.createErr != nil {
		return sessionInfo{}, f.createErr
	}
	session.SessionID = 77
	return session, nil
}

func (f *fakeAPI) FinishSession(_ context.Context, sessionID int64, recordingPath string) error {
	f.finishedID = sessionID
	f.finishedPath = recordingPath
	return f.finishErr
}

func (f *fakeAPI) GetSetting(_ context.Context, _ string) (string, error) {
	return "", nil
}

type memoryStorage struct {
	data map[string]string
}

func (s *memoryStorage) Put(_ context.Context, sessionID string, r io.Reader, _ int64) (string, error) {
	if s.data == nil {
		s.data = map[string]string{}
	}
	raw, err := io.ReadAll(r)
	if err != nil {
		return "", err
	}
	path := "memory://" + sessionID
	s.data[path] = string(raw)
	return path, nil
}

func (s *memoryStorage) Get(_ context.Context, sessionID string) (io.ReadCloser, error) {
	return io.NopCloser(strings.NewReader(s.data[sessionID])), nil
}

func (s *memoryStorage) Delete(_ context.Context, sessionID string) error {
	delete(s.data, sessionID)
	return nil
}

func (s *memoryStorage) URL(_ context.Context, sessionID string, _ time.Duration) (string, error) {
	return sessionID, nil
}

func TestGuacdConfigUsesRDPParametersAndRecording(t *testing.T) {
	cfg := testConfig(t)
	srv := NewServerWithDeps(cfg, &fakeAPI{}, &memoryStorage{})
	req, err := http.NewRequest(http.MethodGet, "/ws/rdp/?width=1280&height=720&dpi=120&security=nla&ignore_cert=false", nil)
	if err != nil {
		t.Fatal(err)
	}
	guacCfg := srv.guacdConfig(authResult{
		Target:  targetConfig{Address: "win.internal", Protocol: "rdp"},
		Account: targetAccount{Username: "alice", Secret: "secret"},
	}, req, "77")
	if guacCfg.Protocol != "rdp" || guacCfg.OptimalScreenWidth != 1280 || guacCfg.OptimalScreenHeight != 720 || guacCfg.OptimalResolution != 120 {
		t.Fatalf("unexpected guac config: %#v", guacCfg)
	}
	want := map[string]string{
		"hostname":              "win.internal",
		"port":                  "3389",
		"username":              "alice",
		"password":              "secret",
		"security":              "nla",
		"ignore-cert":           "false",
		"recording-path":        cfg.Proxy.RDP.RecordingDir(),
		"recording-name":        "77",
		"create-recording-path": "true",
	}
	for key, value := range want {
		if got := guacCfg.Parameters[key]; got != value {
			t.Fatalf("parameter %s=%q want %q", key, got, value)
		}
	}
}

func TestValidateRDPAuthRejectsBadTokenTargets(t *testing.T) {
	tests := []struct {
		name string
		auth authResult
	}{
		{name: "wrong protocol", auth: authResult{Target: targetConfig{Protocol: "ssh", Address: "host"}, Account: targetAccount{Username: "u"}}},
		{name: "missing host", auth: authResult{Target: targetConfig{Protocol: "rdp"}, Account: targetAccount{Username: "u"}}},
		{name: "missing username", auth: authResult{Target: targetConfig{Protocol: "rdp", Address: "host"}}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if err := validateRDPAuth(tt.auth); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
	if err := validateRDPAuth(authResult{Target: targetConfig{Protocol: "rdp", Address: "host"}, Account: targetAccount{Username: "u"}}); err != nil {
		t.Fatalf("valid auth rejected: %v", err)
	}
}

func TestFindRecordingFileSupportsGuacdNames(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "77.guac")
	if err := os.WriteFile(path, []byte("recording"), 0o644); err != nil {
		t.Fatal(err)
	}
	got, err := findRecordingFile(dir, "77")
	if err != nil {
		t.Fatal(err)
	}
	if got != path {
		t.Fatalf("path=%q want %q", got, path)
	}
}

func TestFinishSessionStillMarksFinishedWhenRecordingMissing(t *testing.T) {
	cfg := testConfig(t)
	api := &fakeAPI{}
	srv := NewServerWithDeps(cfg, api, &memoryStorage{})
	err := srv.finishSession(t.Context(), 77, "missing")
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("err=%v", err)
	}
	if api.finishedID != 77 || api.finishedPath != "" {
		t.Fatalf("finished id/path=%d %q", api.finishedID, api.finishedPath)
	}
}

func TestFinishSessionStoresRecordingAndUpdatesSession(t *testing.T) {
	cfg := testConfig(t)
	api := &fakeAPI{}
	storage := &memoryStorage{}
	srv := NewServerWithDeps(cfg, api, storage)
	if err := os.WriteFile(filepath.Join(cfg.Proxy.RDP.RecordingDir(), "77"), []byte("guac-data"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := srv.finishSession(t.Context(), 77, "77"); err != nil {
		t.Fatal(err)
	}
	if api.finishedID != 77 || api.finishedPath != "memory://rdp-77" {
		t.Fatalf("finished id/path=%d %q", api.finishedID, api.finishedPath)
	}
	if storage.data["memory://rdp-77"] != "guac-data" {
		t.Fatalf("stored data=%q", storage.data["memory://rdp-77"])
	}
}

func testConfig(t *testing.T) config.Config {
	t.Helper()
	dir := t.TempDir()
	return config.Config{
		HTTP: config.HTTPConfig{ShutdownTimeoutSeconds: 1},
		Proxy: config.ProxyConfig{
			RDP: config.RDPProxyConfig{
				Addr:                  "127.0.0.1:0",
				GuacdAddr:             "127.0.0.1:1",
				RecordingPath:         dir,
				MaxConnections:        1,
				IdleTimeoutSeconds:    1,
				ConnectTimeoutSeconds: 1,
			},
		},
	}
}
