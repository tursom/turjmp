package sshproxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tursom/turjmp/internal/config"
)

func TestAPIClientVerifyConnectionToken(t *testing.T) {
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/authentication/super-connection-tokens/verify/" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if r.Header.Get("X-Proxy-Auth") != "secret" {
			t.Fatalf("missing proxy auth header")
		}
		var req map[string]string
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if req["token"] != "token-1" || req["remote_addr"] != "1.2.3.4:5555" {
			t.Fatalf("unexpected verify body %#v", req)
		}
		writeEnvelope(t, w, http.StatusOK, map[string]any{
			"token": map[string]any{
				"user_id":        1,
				"asset_id":       2,
				"account_id":     3,
				"protocol":       "ssh",
				"connect_method": "web_cli",
			},
			"target": map[string]any{
				"address":  "ssh.internal",
				"protocol": "ssh",
			},
			"account": map[string]any{
				"username":    "root",
				"secret":      "pw",
				"secret_type": "password",
			},
		})
	}))
	defer ts.Close()

	got, err := newTestAPIClient(ts.URL).VerifyConnectionToken(t.Context(), "token-1", "1.2.3.4:5555")
	if err != nil {
		t.Fatal(err)
	}
	if got.UserID != 1 || got.AssetID != 2 || got.AccountID != 3 {
		t.Fatalf("unexpected ids: %#v", got)
	}
	if got.Target.Address != "ssh.internal" || got.Target.Port != 22 || got.Target.Protocol != "ssh" {
		t.Fatalf("unexpected target: %#v", got.Target)
	}
	if got.Account.Username != "root" || got.Account.Secret != "pw" || got.Account.SecretType != "password" {
		t.Fatalf("unexpected account: %#v", got.Account)
	}
}

func TestAPIClientSessionAuditSettingsRulesAndHostKeys(t *testing.T) {
	var sawCreate, sawFinish, sawAudit, sawSetting, sawRules, sawKeys bool
	ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Proxy-Auth") != "secret" {
			t.Fatalf("missing proxy auth header")
		}
		switch {
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/proxy/sessions":
			sawCreate = true
			var req map[string]any
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatal(err)
			}
			if req["type"] != "sftp" || req["login_from"] != "ssh_client" || req["protocol"] != "ssh" {
				t.Fatalf("unexpected create session body %#v", req)
			}
			writeEnvelope(t, w, http.StatusCreated, map[string]any{"id": 77})
		case r.Method == http.MethodPatch && r.URL.Path == "/api/v1/proxy/sessions/77":
			sawFinish = true
			var req map[string]any
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatal(err)
			}
			if req["is_finished"] != true || req["recording_path"] != "/tmp/77.cast" {
				t.Fatalf("unexpected finish body %#v", req)
			}
			writeEnvelope(t, w, http.StatusOK, map[string]any{})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/proxy/audit-logs":
			sawAudit = true
			var req map[string]any
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatal(err)
			}
			if req["action"] != "sftp.upload" || req["resource"] != "/tmp/a" || req["detail"] != "ok" {
				t.Fatalf("unexpected audit body %#v", req)
			}
			w.WriteHeader(http.StatusNoContent)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/proxy/settings/recording.local.path":
			sawSetting = true
			writeEnvelope(t, w, http.StatusOK, map[string]any{"key": "recording.local.path", "value": `"/var/recordings"`})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/proxy/command-filter-acls":
			sawRules = true
			writeEnvelope(t, w, http.StatusOK, []map[string]any{{"id": 1, "name": "deny-rm", "pattern": "rm -rf", "action": "deny"}})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/proxy/ssh/host-keys":
			sawKeys = true
			writeEnvelope(t, w, http.StatusOK, []map[string]any{{"private_key": "key-a"}, {"private_key": "key-b"}})
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	}))
	defer ts.Close()

	client := newTestAPIClient(ts.URL)
	session, err := client.CreateSession(t.Context(), targetSessionInfo{
		UserID:        1,
		AssetID:       2,
		AccountID:     3,
		Protocol:      "ssh",
		Type:          "sftp",
		ConnectMethod: "ssh_client",
		RemoteAddr:    "1.2.3.4:5555",
	})
	if err != nil {
		t.Fatal(err)
	}
	if session.SessionID != 77 {
		t.Fatalf("session id=%d", session.SessionID)
	}
	if err := client.FinishSession(t.Context(), 77, "/tmp/77.cast"); err != nil {
		t.Fatal(err)
	}
	if err := client.Audit(t.Context(), 1, "sftp.upload", "/tmp/a", "1.2.3.4:5555", "ok"); err != nil {
		t.Fatal(err)
	}
	value, err := client.GetSetting(t.Context(), "recording.local.path")
	if err != nil {
		t.Fatal(err)
	}
	if value != `"/var/recordings"` {
		t.Fatalf("setting=%q", value)
	}
	rules, err := client.ListCommandFilterACLs(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(rules) != 1 || rules[0].Name != "deny-rm" || rules[0].Action != "deny" {
		t.Fatalf("unexpected rules: %#v", rules)
	}
	keys, err := client.GetHostKeys(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(keys, ",") != "key-a,key-b" {
		t.Fatalf("unexpected host keys: %#v", keys)
	}
	if !sawCreate || !sawFinish || !sawAudit || !sawSetting || !sawRules || !sawKeys {
		t.Fatalf("missing calls create=%v finish=%v audit=%v setting=%v rules=%v keys=%v", sawCreate, sawFinish, sawAudit, sawSetting, sawRules, sawKeys)
	}
}

func TestAPIClientErrorEnvelopeAndInvalidJSON(t *testing.T) {
	t.Run("error envelope", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			writeErrorEnvelope(t, w, http.StatusUnauthorized, "unauthorized", "bad token")
		}))
		defer ts.Close()

		_, err := newTestAPIClient(ts.URL).VerifyConnectionToken(t.Context(), "bad", "remote")
		if err == nil || !strings.Contains(err.Error(), "unauthorized: bad token") {
			t.Fatalf("err=%v", err)
		}
	})

	t.Run("invalid json", func(t *testing.T) {
		ts := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte("{"))
		}))
		defer ts.Close()

		_, err := newTestAPIClient(ts.URL).GetSetting(t.Context(), "x")
		if err == nil {
			t.Fatal("expected invalid JSON error")
		}
	})
}

func newTestAPIClient(baseURL string) *APIClient {
	return NewAPIClient(config.Config{
		Proxy: config.ProxyConfig{
			APIBaseURL: baseURL,
		},
		ProxyAuth: config.ProxyAuthConfig{
			Secret: "secret",
		},
	})
}

func writeEnvelope(t *testing.T, w http.ResponseWriter, status int, data any) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if data == nil {
		_, _ = w.Write([]byte(`{"data":null}`))
		return
	}
	if err := json.NewEncoder(w).Encode(map[string]any{"data": data}); err != nil {
		t.Fatal(err)
	}
}

func writeErrorEnvelope(t *testing.T, w http.ResponseWriter, status int, code, message string) {
	t.Helper()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	if err := json.NewEncoder(w).Encode(map[string]any{
		"error": map[string]any{
			"code":    code,
			"message": message,
		},
	}); err != nil {
		t.Fatal(err)
	}
}
