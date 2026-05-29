// Package sshproxy 提供 SSH 代理服务的核心实现。
// 本文件提供连接令牌提取逻辑：原生 SSH 客户端（OpenSSH、Putty 等）连接代理时，
// 传递用户名和密码。用于认证堡垒机 API 的连接令牌可通过 "#" 分隔符嵌入在
// 用户名字段或密码字段中。
package sshproxy

import "strings"

// extractConnectionToken 从用户名或密码中提取连接令牌。
// 支持四种格式，按以下优先级检查：
//  1. 用户名#token — 原生 SSH 客户端将令牌放在登录名中（如 "root#abc123" → 令牌为 "abc123"）
//  2. 密码#token — 令牌通过 "#" 分隔符嵌入在密码字段中
//  3. 密码原值 — 整个密码作为令牌（向后兼容旧客户端）
//  4. 用户名原值 — 仅当密码为空时回退到用户名本身
func extractConnectionToken(username, password string) string {
	username = normalizeTokenCandidate(username)
	password = normalizeTokenCandidate(password)
	for _, candidate := range []string{username, password} {
		if candidate == "" {
			continue
		}
		if idx := strings.LastIndex(candidate, "#"); idx >= 0 && idx < len(candidate)-1 {
			return strings.TrimSpace(candidate[idx+1:])
		}
	}
	if password != "" {
		return password
	}
	return username
}

// normalizeTokenCandidate 清理令牌候选值中的空白字符和 null 字节。
// SSH 客户端或连接字符串可能携带多余的空白符或 \x00 字节，
// 提前清理可避免 API 验证时的匹配失败。
func normalizeTokenCandidate(candidate string) string {
	candidate = strings.Trim(strings.TrimSpace(candidate), "\x00")
	return strings.TrimSpace(candidate)
}
