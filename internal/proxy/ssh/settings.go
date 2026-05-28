// Package sshproxy 提供 SSH 代理服务的核心实现。
// 该文件包含从 API 获取的设置值的解析工具函数。
// API 返回的设置值可能是 JSON 编码的字符串或普通字符串，需要灵活解析。
package sshproxy

import (
	"encoding/json"
	"strconv"
	"strings"
)

// parseSettingString 解析从 API 获取的设置值字符串。
// 解析策略：
// 1. 如果为空，返回 fallback 默认值
// 2. 尝试作为 JSON 字符串解析（处理双重引号的情况）
// 3. 去除两端引号后返回
// 参数 raw 是从 API 获取的原始设置值，fallback 是默认值。
// 返回解析后的字符串值。
func parseSettingString(raw, fallback string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	// 尝试 JSON 解码（API 可能返回 JSON 编码的字符串）
	var out string
	if err := json.Unmarshal([]byte(raw), &out); err == nil {
		if out == "" {
			return fallback
		}
		return out
	}
	// 降级处理：去除两端可能的引号
	return strings.Trim(raw, `"`)
}

// parseSettingInt 解析从 API 获取的设置值整数。
// 解析策略：
// 1. 如果为空，返回 fallback 默认值
// 2. 尝试作为 JSON 数字解析
// 3. 尝试去除引号后作为整数解析
// 参数 raw 是从 API 获取的原始设置值，fallback 是默认值。
// 返回解析后的 int64 值。
func parseSettingInt(raw string, fallback int64) int64 {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return fallback
	}
	// 尝试 JSON 数字解码
	var n int64
	if err := json.Unmarshal([]byte(raw), &n); err == nil {
		return n
	}
	// 降级处理：去除引号后尝试整数解析
	if parsed, err := strconv.ParseInt(strings.Trim(raw, `"`), 10, 64); err == nil {
		return parsed
	}
	return fallback
}
