package sshproxy

import "testing"

// TestExtractConnectionToken 覆盖令牌提取的边界场景：
// 纯密码令牌、用户名#token 优先于密码、密码#token 回退、
// 以及无密码时用户名本身作为回退。
func TestExtractConnectionToken(t *testing.T) {
	tests := []struct {
		name     string
		username string
		password string
		want     string
	}{
		{name: "password token", username: "root", password: "token-1", want: "token-1"},
		{name: "username hash wins over password", username: "root#token-2", password: "target-password", want: "token-2"},
		{name: "password hash fallback", username: "root", password: "ignored#token-3", want: "token-3"},
		{name: "username fallback", username: "token-4", password: "", want: "token-4"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := extractConnectionToken(tt.username, tt.password); got != tt.want {
				t.Fatalf("got %q want %q", got, tt.want)
			}
		})
	}
}
