// package recorder 提供 SSH 会话录制功能，将终端输入输出记录为 asciicast v2 格式的 .cast 文件。
package recorder

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// CastWriter 是 asciicast v2 格式的录制写入器。
// 它将终端事件（输出和窗口大小调整）按时间顺序写入 .cast 文件。
// 文件格式为 JSON Lines：第一行为 header（元信息），后续每行为一个事件。
//
// 每个事件是一个包含三个元素的数组：
//   [时间偏移(秒), 事件类型("o"=输出/"r"=调整大小), 数据]
//
// CastWriter 是线程安全的，使用互斥锁保护并发写入。
type CastWriter struct {
	mu      sync.Mutex // 互斥锁，保护并发写入安全
	file    *os.File   // 底层 .cast 文件句柄
	path    string     // .cast 文件的完整路径
	started time.Time  // 录制开始时间，用于计算事件时间偏移
}

// NewCastWriter 创建一个新的 CastWriter 并写入 asciicast v2 header。
//
// 参数:
//   path   - .cast 文件的保存路径，会自动创建父目录（权限 0755）
//   width  - 终端初始宽度（列数），<=0 时默认 80
//   height - 终端初始行数，<=0 时默认 24
//
// 返回:
//   *CastWriter - 录制写入器
//   error       - 创建文件或写入 header 失败时返回错误
//
// asciicast v2 header 格式:
//
//	{
//	  "version": 2,           // 格式版本，固定为 2
//	  "width": 80,            // 终端宽度（列数）
//	  "height": 24,           // 终端高度（行数）
//	  "timestamp": 123456,    // 录制开始的 Unix 时间戳
//	  "env": { "TERM": "xterm-256color" }  // 终端环境变量
//	}
func NewCastWriter(path string, width, height int) (*CastWriter, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, err
	}
	file, err := os.Create(path)
	if err != nil {
		return nil, err
	}
	w := &CastWriter{file: file, path: path, started: time.Now()}
	if width <= 0 {
		width = 80
	}
	if height <= 0 {
		height = 24
	}
	header := map[string]any{
		"version":   2,
		"width":     width,
		"height":    height,
		"timestamp": w.started.Unix(),
		"env":       map[string]string{"TERM": "xterm-256color"},
	}
	if err := json.NewEncoder(file).Encode(header); err != nil {
		_ = file.Close()
		return nil, err
	}
	return w, nil
}

// Path 返回当前录制 .cast 文件的完整路径。
//
// 如果 CastWriter 为 nil（例如录制功能未启用），返回空字符串 ""。
func (w *CastWriter) Path() string {
	if w == nil {
		return ""
	}
	return w.path
}

// WriteOutput 向 .cast 文件写入一条输出事件。
//
// asciicast v2 输出事件格式:
//
//	[时间偏移秒数(float64), "o", 输出的文本内容(string)]
//
// 参数:
//   p - 终端输出的字节数据
//
// 返回:
//   error - 编码或写入失败时返回错误
//
// 注意:
//   - w 为 nil 或 p 为空时，静默跳过，不写入任何数据
//   - 方法内部加锁，保证并发安全
func (w *CastWriter) WriteOutput(p []byte) error {
	if w == nil || len(p) == 0 {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	event := []any{time.Since(w.started).Seconds(), "o", string(p)}
	return json.NewEncoder(w.file).Encode(event)
}

// WriteResize 向 .cast 文件写入一条终端窗口大小调整事件。
//
// asciicast v2 调整大小事件格式:
//
//	[时间偏移秒数(float64), "r", "列数x行数"(string, 如 "120x40")]
//
// 参数:
//   cols - 新的终端列数
//   rows - 新的终端行数
//
// 返回:
//   error - 编码或写入失败时返回错误
//
// 注意:
//   - w 为 nil、cols<=0 或 rows<=0 时，静默跳过
//   - 方法内部加锁，保证并发安全
func (w *CastWriter) WriteResize(cols, rows int) error {
	if w == nil || cols <= 0 || rows <= 0 {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	event := []any{time.Since(w.started).Seconds(), "r", fmt.Sprintf("%dx%d", cols, rows)}
	return json.NewEncoder(w.file).Encode(event)
}

// Close 关闭 .cast 文件，释放系统资源。
//
// 关闭后不能再写入事件。如果 w 为 nil 或文件已关闭，返回 nil。
// 方法内部加锁，保证并发安全。
func (w *CastWriter) Close() error {
	if w == nil || w.file == nil {
		return nil
	}
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.file.Close()
}

// recordingWriter 是一个 tee/wrapper 模式的 io.Writer 实现。
//
// 原理:
//  Write(p) 被调用时，数据先写入 CastWriter（录制到 .cast 文件），
//  再写入 dst（实际终端 / SSH channel），实现"边输出边录制"的效果。
//
// 用途:
//  在 PTY 输出流上包装一层，同时对用户透明——用户看到正常输出，
//  而所有内容同时被录制下来。
type recordingWriter struct {
	dst io.Writer    // 实际输出目标（SSH channel / 终端）
	rec *CastWriter  // 录制写入器（.cast 文件）
}

// NewRecordingWriter 创建一个 recordingWriter，将数据同时写入 dst 和 rec。
//
// 参数:
//   dst - 实际输出目标（通常是 SSH 会话的 channel 或 PTY）
//   rec - CastWriter 实例，用于录制
//
// 返回:
//   io.Writer - 可作为 PTY 输出流使用的 writer
//
// 典型用法:
//
//	rec, _ := NewCastWriter("/var/recordings/session.cast", 80, 24)
//	rw := NewRecordingWriter(sshChannel, rec)
//	// 将 rw 用作 PTY 的 stdout，所有输出既发送给用户又写入 .cast
func NewRecordingWriter(dst io.Writer, rec *CastWriter) io.Writer {
	return &recordingWriter{dst: dst, rec: rec}
}

// Write 实现 io.Writer 接口。
//
// 执行顺序:
//  1. 调用 rec.WriteOutput(p) 将数据写入 .cast 文件
//  2. 调用 dst.Write(p) 将数据写入实际输出目标
//
// 如果录制写入失败，立即返回错误（不会写入 dst），
// 确保录制失败时能被上层感知和处理。
//
// 返回:
//   n     - 写入 dst 的字节数
//   error - 录制失败或 dst 写入失败时返回错误
func (w *recordingWriter) Write(p []byte) (int, error) {
	if err := w.rec.WriteOutput(p); err != nil {
		return 0, err
	}
	return w.dst.Write(p)
}
