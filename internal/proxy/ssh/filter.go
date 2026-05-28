// Package sshproxy 提供 SSH 代理服务的核心实现。
// 该文件实现基于正则表达式的命令过滤系统。
// 通过正则匹配用户输入的命令，根据规则执行 deny（拒绝）或 review（审查）等操作。
package sshproxy

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"regexp"
	"strings"
)

// commandFilterRule 表示一条从 API 服务器获取的命令过滤规则。
// 规则包含正则匹配模式和对应的动作（deny/reject/review 等）。
type commandFilterRule struct {
	ID      int64  `json:"id"`      // 规则唯一标识
	Name    string `json:"name"`    // 规则名称
	Pattern string `json:"pattern"` // 正则表达式匹配模式
	Action  string `json:"action"`  // 匹配后的动作：deny（拒绝）、reject（拒绝）、review（审查）
}

// commandFilter 是命令过滤器的核心结构体。
// 包含所有已编译的过滤规则。
type commandFilter struct {
	rules []compiledRule // 已编译的过滤规则列表
}

// compiledRule 表示一条已编译的命令过滤规则。
// 预编译正则表达式以提高匹配性能。
type compiledRule struct {
	Name    string         // 规则名称
	Action  string         // 匹配后的动作
	Pattern string         // 原始正则表达式字符串
	re      *regexp.Regexp // 编译后的正则表达式对象
}

// loadCommandFilter 从 API 服务器加载命令过滤规则并编译正则表达式。
// 该函数会过滤掉无效的规则（空模式、无效正则）。
// 参数 ctx 是上下文，api 是 API 客户端接口。
// 返回编译后的命令过滤器，如果获取规则失败则返回错误。
func loadCommandFilter(ctx context.Context, api apiClient) (*commandFilter, error) {
	rules, err := api.ListCommandFilterACLs(ctx)
	if err != nil {
		return nil, err
	}
	filter := &commandFilter{}
	for _, rule := range rules {
		// 跳过空模式规则
		if strings.TrimSpace(rule.Pattern) == "" {
			continue
		}
		// 尝试编译正则表达式，失败则跳过
		re, err := regexp.Compile(rule.Pattern)
		if err != nil {
			continue
		}
		// 默认为 reject 动作
		action := strings.ToLower(strings.TrimSpace(rule.Action))
		if action == "" {
			action = "reject"
		}
		filter.rules = append(filter.rules, compiledRule{
			Name:    rule.Name,
			Action:  action,
			Pattern: rule.Pattern,
			re:      re,
		})
	}
	return filter, nil
}

// match 检查输入行是否匹配任何过滤规则。
// 匹配前会先剔除控制字符（除了 tab、换行和回车）。
// 返回第一个匹配的规则和是否匹配的标志。
// 参数 line 是要检查的命令行文本。
func (f *commandFilter) match(line string) (compiledRule, bool) {
	if f == nil {
		return compiledRule{}, false
	}
	trimmed := strings.TrimSpace(stripControls(line))
	for _, rule := range f.rules {
		if rule.re.MatchString(trimmed) {
			return rule, true
		}
	}
	return compiledRule{}, false
}

// stripControls 去除字符串中的控制字符，保留常见的空白字符。
// 保留 tab (\t)、换行 (\n) 和回车 (\r)，删除其他不可打印字符。
// 参数 s 是原始字符串。
// 返回清理后的字符串。
func stripControls(s string) string {
	var out strings.Builder
	for _, r := range s {
		switch {
		case r == '\t' || r == '\n' || r == '\r':
			// 保留关键的格式字符
			out.WriteRune(r)
		case r >= 0x20 && r != 0x7f:
			// 保留正常的可打印字符（排除 DEL 删除字符）
			out.WriteRune(r)
		}
	}
	return out.String()
}

// filteringReader 实现过滤读取器，在数据流转发过程中实时过滤敏感命令。
// 该读取器逐行收集数据，当检测到完整行时进行命令匹配检查。
// 被拒绝的行不会传递给目标，而是向用户发送拒绝通知。
type filteringReader struct {
	src    io.Reader        // 原始数据源（用户输入）
	notify io.Writer        // 通知输出（向用户显示拒绝信息）
	filter *commandFilter   // 命令过滤器实例
	buf    bytes.Buffer     // 已通过过滤的待输出缓冲区
	line   bytes.Buffer     // 当前正在收集的行缓冲区
}

// newFilteringReader 创建一个新的过滤读取器。
// 如果过滤器为空或没有规则，直接返回原始读取器以跳过过滤开销。
// 参数 src 是原始数据源，notify 是通知输出，filter 是命令过滤器。
func newFilteringReader(src io.Reader, notify io.Writer, filter *commandFilter) io.Reader {
	if filter == nil || len(filter.rules) == 0 {
		return src
	}
	return &filteringReader{src: src, notify: notify, filter: filter}
}

// Read 实现 io.Reader 接口，从过滤后的缓冲区中读取数据。
// 如果缓冲区为空，则从原始数据源读取数据并经过过滤后填充缓冲区。
// 参数 p 是目标缓冲区。
// 返回读取的字节数和可能的错误。
func (r *filteringReader) Read(p []byte) (int, error) {
	// 当过滤缓冲区为空时，持续从原始数据源读取并进行过滤
	for r.buf.Len() == 0 {
		tmp := make([]byte, len(p))
		if len(tmp) == 0 {
			tmp = make([]byte, 1)
		}
		n, err := r.src.Read(tmp)
		if n > 0 {
			// 对读取的数据进行逐行过滤
			r.writeFiltered(tmp[:n])
		}
		if err != nil {
			// 如果发生错误但缓冲区仍有数据，先让用户读取缓冲数据
			if r.buf.Len() > 0 {
				break
			}
			return 0, err
		}
	}
	return r.buf.Read(p)
}

// writeFiltered 对原始数据进行逐字节逐行的过滤处理。
// 每收集到完整的一行（以 \n 或 \r 结尾），就检查是否匹配拒绝规则。
// 匹配 deny/reject 规则的行会被丢弃并向用户发送拒绝通知。
// 通过检查的行保留在输出缓冲区中。
func (r *filteringReader) writeFiltered(data []byte) {
	for _, b := range data {
		r.line.WriteByte(b)
		// 如果不是行结束符，继续收集
		if b != '\n' && b != '\r' {
			continue
		}
		// 得到完整的一行
		line := r.line.String()
		r.line.Reset()
		// 检查该行是否匹配拒绝规则
		if rule, ok := r.filter.match(line); ok && (rule.Action == "deny" || rule.Action == "reject") {
			// 向用户发送命令被拒绝的通知
			_, _ = fmt.Fprintf(r.notify, "\r\ncommand rejected by policy: %s\r\n", rule.Name)
			continue
		}
		// 通过检查的行写入输出缓冲区
		r.buf.WriteString(line)
	}
}
