package sshproxy

import "testing"

func TestParseSettingString(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		fallback string
		want     string
	}{
		{name: "blank", raw: " ", fallback: "fallback", want: "fallback"},
		{name: "json string", raw: `"./recordings"`, fallback: "fallback", want: "./recordings"},
		{name: "empty json string", raw: `""`, fallback: "fallback", want: "fallback"},
		{name: "plain", raw: "plain", fallback: "fallback", want: "plain"},
		{name: "broken quote", raw: `"plain`, fallback: "fallback", want: "plain"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseSettingString(tt.raw, tt.fallback); got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
		})
	}
}

func TestParseSettingInt(t *testing.T) {
	tests := []struct {
		name     string
		raw      string
		fallback int64
		want     int64
	}{
		{name: "blank", raw: "", fallback: 42, want: 42},
		{name: "json number", raw: "900", fallback: 42, want: 900},
		{name: "quoted number", raw: `"1073741824"`, fallback: 42, want: 1073741824},
		{name: "invalid", raw: "abc", fallback: 42, want: 42},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseSettingInt(tt.raw, tt.fallback); got != tt.want {
				t.Fatalf("got %d want %d", got, tt.want)
			}
		})
	}
}
