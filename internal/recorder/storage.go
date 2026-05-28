// package recorder 提供 SSH 会话录制功能，将终端输入输出记录为 asciicast v2 格式的 .cast 文件。
package recorder

import (
	"context"
	"io"
	"os"
	"path/filepath"
	"time"
)

// StorageBackend 定义录制文件存储后端的抽象接口。
//
// 通过该接口，录制系统可以在不修改业务逻辑的情况下切换存储方案：
//   - LocalStorage: 本地文件系统存储（默认实现）
//   - 未来扩展: S3、OSS、NAS 等远程存储
//
// 所有方法都接受 context.Context，支持超时控制和请求取消。
type StorageBackend interface {
	// Put 将录制数据持久化到存储后端。
	//
	// 参数:
	//   ctx       - 上下文，用于超时控制和取消
	//   sessionID - 会话唯一标识，用于生成存储路径
	//   r         - 录制数据的读取器
	//   size      - 数据大小（字节），实现层可以忽略（如本地存储不需要）
	//
	// 返回:
	//   string - 存储后的访问路径或 key
	//   error  - 写入失败时返回错误
	Put(ctx context.Context, sessionID string, r io.Reader, size int64) (string, error)

	// Get 从存储后端读取会话录制数据。
	//
	// 参数:
	//   ctx       - 上下文
	//   sessionID - 会话唯一标识
	//
	// 返回:
	//   io.ReadCloser - 录制数据的可读流，调用方负责关闭
	//   error         - 文件不存在或读取失败时返回错误
	Get(ctx context.Context, sessionID string) (io.ReadCloser, error)

	// Delete 从存储后端删除指定会话的录制数据。
	//
	// 参数:
	//   ctx       - 上下文
	//   sessionID - 会话唯一标识
	//
	// 返回:
	//   error - 删除失败时返回错误
	Delete(ctx context.Context, sessionID string) error

	// URL 返回录制文件的可访问地址。
	//
	// 参数:
	//   ctx       - 上下文
	//   sessionID - 会话唯一标识
	//   expire    - URL 有效期，用于生成预签名 URL（如 S3），本地存储忽略此参数
	//
	// 返回:
	//   string - 文件 URL 或访问路径
	//   error  - 生成失败时返回错误
	URL(ctx context.Context, sessionID string, expire time.Duration) (string, error)
}

// LocalStorage 是 StorageBackend 的本地文件系统实现。
//
// 录制文件存储在 BasePath 目录下，文件名为 {sessionID}.cast。
//
// 典型用法:
//
//	s := NewLocalStorage("/var/turjmp/recordings")
//	path, _ := s.Put(ctx, "session-123", reader, 0)
type LocalStorage struct {
	BasePath string // 录制文件的存储根目录
}

// NewLocalStorage 创建一个本地文件系统存储后端。
//
// 参数:
//   basePath - 录制文件的存储根目录，为空时默认使用 "./recordings"
//
// 返回:
//   *LocalStorage - 本地存储实例
func NewLocalStorage(basePath string) *LocalStorage {
	if basePath == "" {
		basePath = "./recordings"
	}
	return &LocalStorage{BasePath: basePath}
}

// Put 将会话录制数据写入本地文件系统。
//
// 实现细节:
//   - 自动创建 BasePath 目录（权限 0755），目录不存在时自动创建
//   - 文件名格式: {BasePath}/{sessionID}.cast
//   - 流式写入: 使用 io.Copy 从 reader 复制数据到文件
//   - size 参数被忽略（本地存储不需要预知文件大小）
//
// 参数:
//   ctx       - 上下文，函数返回时检查 ctx.Err() 是否因取消而结束
//   sessionID - 会话 ID，用于生成文件名
//   r         - 录制数据的读取源
//   _         - 数据大小，本地存储忽略此参数
//
// 返回:
//   string - 文件的完整路径
//   error  - 创建目录、创建文件或写入失败时返回错误；
//            上下文被取消时返回 ctx.Err()
func (s *LocalStorage) Put(ctx context.Context, sessionID string, r io.Reader, _ int64) (string, error) {
	if err := os.MkdirAll(s.BasePath, 0o755); err != nil {
		return "", err
	}
	path := s.path(sessionID)
	file, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	if _, err := io.Copy(file, r); err != nil {
		return "", err
	}
	return path, ctx.Err()
}

// Get 从本地文件系统读取会话录制数据。
//
// 参数:
//   _         - 上下文，本地读取不使用（文件打开是同步操作）
//   sessionID - 会话 ID
//
// 返回:
//   io.ReadCloser - 文件的只读句柄，调用方负责关闭
//   error         - 文件不存在或无法打开时返回错误
func (s *LocalStorage) Get(_ context.Context, sessionID string) (io.ReadCloser, error) {
	return os.Open(s.path(sessionID))
}

// Delete 从本地文件系统删除会话录制数据。
//
// 参数:
//   _         - 上下文，本地删除不使用
//   sessionID - 会话 ID
//
// 返回:
//   error - 删除失败时返回错误（文件不存在也会返回错误）
func (s *LocalStorage) Delete(_ context.Context, sessionID string) error {
	return os.Remove(s.path(sessionID))
}

// URL 返回录制文件的本地路径作为可访问地址。
//
// 本地存储不支持预签名 URL，直接返回文件的绝对路径。
// expire 参数被忽略，因为本地文件路径没有过期概念。
//
// 参数:
//   _         - 上下文，本地操作不使用
//   sessionID - 会话 ID
//   _         - 过期时间，本地存储忽略
//
// 返回:
//   string - 文件的完整路径
//   error  - 始终为 nil（本地路径生成不会失败）
func (s *LocalStorage) URL(_ context.Context, sessionID string, _ time.Duration) (string, error) {
	return s.path(sessionID), nil
}

// path 根据 sessionID 拼接 .cast 文件的完整路径。
//
// 格式: {BasePath}/{sessionID}.cast
//
// 内部辅助方法，不对外暴露。
func (s *LocalStorage) path(sessionID string) string {
	return filepath.Join(s.BasePath, sessionID+".cast")
}
