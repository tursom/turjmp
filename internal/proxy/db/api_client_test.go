package dbproxy

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/tursom/turjmp/internal/config"
)

func TestAPIClientVerifyConnectionToken(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v1/authentication/super-connection-tokens/verify/" {
			t.Fatalf("unexpected path %s", r.URL.Path)
		}
		if r.Header.Get("X-Proxy-Auth") != "secret" {
			t.Fatalf("missing proxy auth header")
		}
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if req["token"] != "token-1" || req["remote_addr"] != "1.2.3.4:5555" || req["expected_protocol"] != "mysql" || req["consume"] != true {
			t.Fatalf("unexpected verify body %#v", req)
		}
		writeEnvelope(t, w, http.StatusOK, map[string]any{
			"token": map[string]any{
				"user_id":        1,
				"asset_id":       2,
				"account_id":     3,
				"connect_method": "web_db",
			},
			"target": map[string]any{
				"address":  "db.internal",
				"protocol": "mysql",
			},
			"account": map[string]any{
				"username":    "root",
				"secret":      "pw",
				"secret_type": "password",
				"db_name":     "app",
			},
		})
	})

	client := newTestAPIClient(handler)
	got, err := client.VerifyConnectionToken(t.Context(), "token-1", "1.2.3.4:5555", "mysql")
	if err != nil {
		t.Fatal(err)
	}
	if got.UserID != 1 || got.AssetID != 2 || got.AccountID != 3 {
		t.Fatalf("unexpected ids: %#v", got)
	}
	if got.Target.Address != "db.internal" || got.Target.Port != 3306 || got.Target.Protocol != "mysql" {
		t.Fatalf("unexpected target: %#v", got.Target)
	}
	if got.Account.Username != "root" || got.Account.Secret != "pw" || got.Account.DBName != "app" {
		t.Fatalf("unexpected account: %#v", got.Account)
	}
	if got.ConnectMethod != "web_db" {
		t.Fatalf("connect method=%q want web_db", got.ConnectMethod)
	}
}

func TestAPIClientPreflightConnectionTokenDoesNotConsume(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req map[string]any
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			t.Fatal(err)
		}
		if req["token"] != "token-1" || req["expected_protocol"] != "postgres" || req["consume"] != false {
			t.Fatalf("unexpected preflight body %#v", req)
		}
		writeEnvelope(t, w, http.StatusOK, map[string]any{
			"token": map[string]any{
				"user_id":        1,
				"asset_id":       2,
				"account_id":     3,
				"connect_method": "web_db",
			},
			"target": map[string]any{"address": "pg.internal", "protocol": "postgres"},
			"account": map[string]any{
				"username":    "postgres",
				"secret":      "pw",
				"secret_type": "password",
			},
		})
	})

	got, err := newTestAPIClient(handler).PreflightConnectionToken(t.Context(), "token-1", "remote", "postgres")
	if err != nil {
		t.Fatal(err)
	}
	if got.Target.Protocol != "postgres" || got.ConnectMethod != "web_db" {
		t.Fatalf("unexpected auth result: %#v", got)
	}
}

func TestAPIClientSessionAuditAndSettingCalls(t *testing.T) {
	var sawCreate, sawGetSession, sawFinish, sawAudit, sawSetting bool
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
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
			if req["type"] != "db_proxy" || req["login_from"] != "mysql_client" || req["protocol"] != "mysql" {
				t.Fatalf("unexpected create session body %#v", req)
			}
			writeEnvelope(t, w, http.StatusCreated, map[string]any{"id": 77})
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/proxy/sessions/77":
			sawGetSession = true
			writeEnvelope(t, w, http.StatusOK, map[string]any{
				"id":          77,
				"user_id":     1,
				"asset_id":    2,
				"account_id":  3,
				"protocol":    "mysql",
				"type":        "db_terminal",
				"login_from":  "web_db",
				"remote_addr": "1.2.3.4:5555",
				"is_finished": true,
			})
		case r.Method == http.MethodPatch && r.URL.Path == "/api/v1/proxy/sessions/77":
			sawFinish = true
			var req map[string]any
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatal(err)
			}
			if req["is_finished"] != true {
				t.Fatalf("unexpected finish body %#v", req)
			}
			writeEnvelope(t, w, http.StatusOK, map[string]any{})
		case r.Method == http.MethodPost && r.URL.Path == "/api/v1/proxy/audit-logs":
			sawAudit = true
			var req map[string]any
			if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
				t.Fatal(err)
			}
			if req["action"] != "db.query" || req["resource"] != "mysql" || req["detail"] != "{}" {
				t.Fatalf("unexpected audit body %#v", req)
			}
			writeEnvelope(t, w, http.StatusNoContent, nil)
		case r.Method == http.MethodGet && r.URL.Path == "/api/v1/proxy/settings/proxy.db.max_connections":
			sawSetting = true
			writeEnvelope(t, w, http.StatusOK, map[string]any{"value": "50"})
		default:
			t.Fatalf("unexpected request %s %s", r.Method, r.URL.Path)
		}
	})

	client := newTestAPIClient(handler)
	session, err := client.CreateSession(t.Context(), sessionInfo{
		UserID:        1,
		AssetID:       2,
		AccountID:     3,
		Protocol:      "mysql",
		Type:          "db_proxy",
		ConnectMethod: "mysql_client",
		RemoteAddr:    "1.2.3.4:5555",
	})
	if err != nil {
		t.Fatal(err)
	}
	if session.SessionID != 77 {
		t.Fatalf("session id=%d", session.SessionID)
	}
	current, err := client.GetSession(t.Context(), 77)
	if err != nil {
		t.Fatal(err)
	}
	if !current.IsFinished || current.SessionID != 77 || current.ConnectMethod != "web_db" {
		t.Fatalf("unexpected current session: %#v", current)
	}
	if err := client.FinishSession(t.Context(), 77); err != nil {
		t.Fatal(err)
	}
	if err := client.Audit(t.Context(), 1, "db.query", "mysql", "1.2.3.4:5555", "{}"); err != nil {
		t.Fatal(err)
	}
	value, err := client.GetSetting(t.Context(), "proxy.db.max_connections")
	if err != nil {
		t.Fatal(err)
	}
	if value != "50" {
		t.Fatalf("setting=%q", value)
	}
	if !sawCreate || !sawGetSession || !sawFinish || !sawAudit || !sawSetting {
		t.Fatalf("missing calls create=%v get=%v finish=%v audit=%v setting=%v", sawCreate, sawGetSession, sawFinish, sawAudit, sawSetting)
	}
}

func TestAPIClientErrorEnvelope(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		writeErrorEnvelope(t, w, http.StatusUnauthorized, "unauthorized", "bad token")
	})

	_, err := newTestAPIClient(handler).VerifyConnectionToken(t.Context(), "bad", "remote", "mysql")
	if err == nil || !strings.Contains(err.Error(), "unauthorized: bad token") {
		t.Fatalf("err=%v", err)
	}
}

func TestAPIClientInvalidJSON(t *testing.T) {
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("{"))
	})

	_, err := newTestAPIClient(handler).GetSetting(t.Context(), "x")
	if err == nil {
		t.Fatal("expected invalid JSON error")
	}
}

func newTestAPIClient(handler http.Handler) *APIClient {
	client := NewAPIClient(config.Config{
		Proxy: config.ProxyConfig{
			APIBaseURL: "http://turjmp.test",
		},
		ProxyAuth: config.ProxyAuthConfig{
			Secret: "secret",
		},
	})
	client.http.Transport = roundTripFunc(func(req *http.Request) (*http.Response, error) {
		rec := httptest.NewRecorder()
		handler.ServeHTTP(rec, req)
		return rec.Result(), nil
	})
	return client
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(req *http.Request) (*http.Response, error) {
	return f(req)
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
