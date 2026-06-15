package config

import "testing"

func TestEnvConfigKeySupportsNestedUnderscoreFields(t *testing.T) {
	tests := map[string]string{
		"TURJMP_HTTP_ADDR":                      "http.addr",
		"TURJMP_DATABASE_DSN":                   "database.dsn",
		"TURJMP_PROXY_RDP_NATIVE_ENABLED":       "proxy.rdp.native_enabled",
		"TURJMP_PROXY__RDP__NATIVE_ENABLED":     "proxy.rdp.native_enabled",
		"TURJMP_PROXY__RDP__NATIVE_ENGINE_PATH": "proxy.rdp.native_engine_path",
		"TURJMP_RATE_LIMIT_REQUESTS_PER_SECOND": "rate_limit.requests_per_second",
		"TURJMP_PROXY_AUTH_SECRET":              "proxy_auth.secret",
	}
	for input, want := range tests {
		if got := envConfigKey(input); got != want {
			t.Fatalf("envConfigKey(%q)=%q want %q", input, got, want)
		}
	}
}
