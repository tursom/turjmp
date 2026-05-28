// Package sshproxy 提供 SSH 代理服务的核心实现。
// 该文件实现 SFTP 代理，在用户和目标资产之间代理 SFTP 文件传输请求，
// 同时实施路径黑名单和文件大小限制策略。
package sshproxy

import (
	"errors"
	"io"
	"os"
	"path"
	"strings"

	"github.com/pkg/sftp"
)

// sftpPolicy 定义 SFTP 代理的策略配置。
// 包含文件大小上限和禁止访问的路径列表。
type sftpPolicy struct {
	MaxFileSize int64    // 单个文件的最大上传大小（字节），0 表示不限制
	DenyPaths   []string // 禁止访问的文件路径列表
}

// remoteSFTPHandlers 实现 SFTP 请求的代理处理器。
// 该结构体实现了 sftp.Handlers 接口的所有方法，在用户请求和远程 SFTP 服务器之间进行代理，
// 同时对文件操作实施策略检查（路径黑名单、文件大小限制）和审计记录。
type remoteSFTPHandlers struct {
	client *sftp.Client // 远程 SFTP 客户端，用于转发请求
	policy sftpPolicy   // SFTP 访问策略配置
	audit  func(action, resource, detail string) // 审计回调函数
}

// Fileread 处理 SFTP 文件下载请求。
// 先检查路径是否允许访问，记录审计日志，然后从远程打开文件。
// 参数 req 是 SFTP 请求对象，包含文件路径等信息。
// 返回可随机读取的文件读取器，如果路径被拒绝或打开失败则返回错误。
func (h *remoteSFTPHandlers) Fileread(req *sftp.Request) (io.ReaderAt, error) {
	if err := h.checkPath(req.Filepath); err != nil {
		return nil, err
	}
	h.auditAction("download", req.Filepath, "")
	return h.client.Open(req.Filepath)
}

// Filewrite 处理 SFTP 文件上传请求。
// 先检查路径是否允许访问，记录审计日志，然后打开远程文件进行写入。
// 如果配置了文件大小限制，会包装为 limitedSFTPWriter 进行写入量监控。
// 参数 req 是 SFTP 请求对象，包含文件路径和打开标志。
// 返回可随机写入的文件写入器，如果路径被拒绝或打开失败则返回错误。
func (h *remoteSFTPHandlers) Filewrite(req *sftp.Request) (io.WriterAt, error) {
	if err := h.checkPath(req.Filepath); err != nil {
		return nil, err
	}
	h.auditAction("upload", req.Filepath, "")
	// 将 SFTP 打开标志转换为 POSIX 标志
	flags := openFlags(req.Pflags())
	f, err := h.client.OpenFile(req.Filepath, flags)
	if err != nil {
		return nil, err
	}
	// 如果配置了文件大小上限，包装为受限写入器
	if h.policy.MaxFileSize > 0 {
		return &limitedSFTPWriter{File: f, max: h.policy.MaxFileSize}, nil
	}
	return f, nil
}

// OpenFile 处理 SFTP 文件打开请求（可读写）。
// 先检查路径是否允许访问，记录审计日志，然后打开远程文件。
// 如果配置了文件大小限制，会包装为 limitedSFTPRW 进行读写大小监控。
// 参数 req 是 SFTP 请求对象。
// 返回可随机读写的文件句柄，如果路径被拒绝或打开失败则返回错误。
func (h *remoteSFTPHandlers) OpenFile(req *sftp.Request) (sftp.WriterAtReaderAt, error) {
	if err := h.checkPath(req.Filepath); err != nil {
		return nil, err
	}
	h.auditAction("open", req.Filepath, "")
	f, err := h.client.OpenFile(req.Filepath, openFlags(req.Pflags()))
	if err != nil {
		return nil, err
	}
	// 如果配置了文件大小上限，包装为受限读写器
	if h.policy.MaxFileSize > 0 {
		return &limitedSFTPRW{File: f, max: h.policy.MaxFileSize}, nil
	}
	return f, nil
}

// Filecmd 处理 SFTP 文件管理命令请求（删除、重命名、创建目录等）。
// 支持的命令包括：Remove（删除文件）、Rename/PosixRename（重命名）、
// Rmdir（删除目录）、Mkdir（创建目录）、Setstat（设置文件属性）。
// 所有操作前都会进行路径检查。
// 参数 req 是 SFTP 请求对象。
// 返回 nil 表示成功，否则返回错误。
func (h *remoteSFTPHandlers) Filecmd(req *sftp.Request) error {
	if err := h.checkPath(req.Filepath); err != nil {
		return err
	}
	switch req.Method {
	case "Remove":
		h.auditAction("delete", req.Filepath, "")
		return h.client.Remove(req.Filepath)
	case "Rename", "PosixRename":
		// 重命名操作需要同时检查源路径和目标路径
		if err := h.checkPath(req.Target); err != nil {
			return err
		}
		h.auditAction("rename", req.Filepath, req.Target)
		return h.client.Rename(req.Filepath, req.Target)
	case "Rmdir":
		h.auditAction("rmdir", req.Filepath, "")
		return h.client.RemoveDirectory(req.Filepath)
	case "Mkdir":
		h.auditAction("mkdir", req.Filepath, "")
		return h.client.Mkdir(req.Filepath)
	case "Setstat":
		// 处理文件属性设置：截断大小、权限修改、时间修改
		attrs := req.Attributes()
		flags := req.AttrFlags()
		if flags.Size {
			if err := h.client.Truncate(req.Filepath, int64(attrs.Size)); err != nil {
				return err
			}
		}
		if flags.Permissions {
			if err := h.client.Chmod(req.Filepath, attrs.FileMode()); err != nil {
				return err
			}
		}
		if flags.Acmodtime {
			if err := h.client.Chtimes(req.Filepath, attrs.AccessTime(), attrs.ModTime()); err != nil {
				return err
			}
		}
		return nil
	default:
		return errors.New("unsupported sftp command: " + req.Method)
	}
}

// auditAction 调用审计回调函数记录 SFTP 操作。
// 如果审计回调为 nil 则跳过。
// 参数 action 是操作类型（download/upload/delete 等），
// resource 是操作的资源路径，detail 是补充信息。
func (h *remoteSFTPHandlers) auditAction(action, resource, detail string) {
	if h.audit != nil {
		h.audit(action, resource, detail)
	}
}

// Filelist 处理 SFTP 文件列表请求。
// 支持 List（列出目录内容）和 Stat（获取单个文件信息）方法。
// 参数 req 是 SFTP 请求对象。
// 返回文件列表迭代器，如果路径被拒绝或操作失败则返回错误。
func (h *remoteSFTPHandlers) Filelist(req *sftp.Request) (sftp.ListerAt, error) {
	if err := h.checkPath(req.Filepath); err != nil {
		return nil, err
	}
	switch req.Method {
	case "List":
		// 列出目录内容
		files, err := h.client.ReadDir(req.Filepath)
		if err != nil {
			return nil, err
		}
		return fileInfoList(files), nil
	default:
		// Stat：获取单个文件信息
		info, err := h.client.Stat(req.Filepath)
		if err != nil {
			return nil, err
		}
		// 将文件名替换为请求路径的基础名称
		return fileInfoList{renameFileInfo{name: path.Base(req.Filepath), FileInfo: info}}, nil
	}
}

// checkPath 检查给定的文件路径是否在策略允许范围内。
// 将路径标准化后，与 denyPaths 黑名单进行前缀匹配或精确匹配检查。
// 参数 p 是要检查的文件路径。
// 返回 nil 表示路径允许访问，否则返回错误。
func (h *remoteSFTPHandlers) checkPath(p string) error {
	cleaned := path.Clean("/" + strings.TrimPrefix(p, "/"))
	for _, deny := range h.policy.DenyPaths {
		deny = strings.TrimSpace(deny)
		if deny == "" {
			continue
		}
		deny = path.Clean("/" + strings.TrimPrefix(deny, "/"))
		// 精确匹配或前缀匹配（子目录也禁止）
		if cleaned == deny || strings.HasPrefix(cleaned, deny+"/") {
			return errors.New("path denied by policy")
		}
	}
	return nil
}

// openFlags 将 SFTP 的文件打开标志转换为 POSIX 兼容的标志位。
// 支持只读/只写/读写模式、追加、创建、截断和排他创建标志。
// 参数 flags 是 SFTP 的文件打开标志。
// 返回 POSIX 兼容的标志位组合。
func openFlags(flags sftp.FileOpenFlags) int {
	out := 0
	// 读写模式
	switch {
	case flags.Read && flags.Write:
		out |= os.O_RDWR
	case flags.Write:
		out |= os.O_WRONLY
	default:
		out |= os.O_RDONLY
	}
	// 追加模式
	if flags.Append {
		out |= os.O_APPEND
	}
	// 创建文件
	if flags.Creat {
		out |= os.O_CREATE
	}
	// 打开时截断文件
	if flags.Trunc {
		out |= os.O_TRUNC
	}
	// 排他创建（文件已存在时失败）
	if flags.Excl {
		out |= os.O_EXCL
	}
	return out
}

// fileInfoList 实现 sftp.ListerAt 接口，将 os.FileInfo 切片转换为可迭代的列表。
// 使用 []os.FileInfo 底层类型，支持从指定偏移量开始列出文件信息。
type fileInfoList []os.FileInfo

// ListAt 实现 sftp.ListerAt 接口。
// 从指定偏移量开始，将文件信息复制到目标切片中。
// 参数 dst 是目标文件信息切片，offset 是起始偏移量。
// 返回实际复制的数量，如果超出范围则返回 io.EOF。
func (l fileInfoList) ListAt(dst []os.FileInfo, offset int64) (int, error) {
	if offset >= int64(len(l)) {
		return 0, io.EOF
	}
	n := copy(dst, l[offset:])
	if int(offset)+n >= len(l) {
		return n, io.EOF
	}
	return n, nil
}

// renameFileInfo 包装 os.FileInfo 以覆盖文件名称。
// 用于 Stat 请求中返回指定路径的文件名而非原始名称。
type renameFileInfo struct {
	name string       // 自定义文件名
	os.FileInfo       // 嵌入原始文件信息
}

// Name 返回自定义的文件名，如果未设置则使用原始文件信息的名称。
func (i renameFileInfo) Name() string {
	if i.name == "" {
		return i.FileInfo.Name()
	}
	return i.name
}

// limitedSFTPWriter 实现 SFTP 写入器的文件大小限制。
// 在写入前检查偏移量加上数据长度是否超过最大文件大小。
type limitedSFTPWriter struct {
	*sftp.File // 嵌入 SFTP 文件句柄
	max int64  // 最大允许的文件大小
}

// WriteAt 实现 io.WriterAt 接口，带文件大小限制检查。
// 如果写入后的文件大小超过 max，返回错误。
func (w *limitedSFTPWriter) WriteAt(p []byte, off int64) (int, error) {
	if off+int64(len(p)) > w.max {
		return 0, errors.New("file exceeds configured max size")
	}
	return w.File.WriteAt(p, off)
}

// limitedSFTPRW 实现 SFTP 读写器的文件大小限制。
// 同时支持限大小的写入和普通的读取操作。
type limitedSFTPRW struct {
	*sftp.File // 嵌入 SFTP 文件句柄
	max int64  // 最大允许的文件大小
}

// WriteAt 实现 io.WriterAt 接口，带文件大小限制检查。
func (w *limitedSFTPRW) WriteAt(p []byte, off int64) (int, error) {
	if off+int64(len(p)) > w.max {
		return 0, errors.New("file exceeds configured max size")
	}
	return w.File.WriteAt(p, off)
}

// ReadAt 实现 io.ReaderAt 接口，读取操作不做限制。
func (w *limitedSFTPRW) ReadAt(p []byte, off int64) (int, error) {
	return w.File.ReadAt(p, off)
}

// parseSFTPPolicy 从 API 设置值解析 SFTP 策略配置。
// 参数 maxValue 是文件大小上限的设置值，denyValue 是路径黑名单的设置值。
// 返回解析后的 SFTP 策略对象，默认最大文件大小为 1GB，默认禁止路径为 /etc/shadow 和 /etc/passwd。
func parseSFTPPolicy(maxValue, denyValue string) sftpPolicy {
	// 默认最大文件大小 1GB
	policy := sftpPolicy{MaxFileSize: parseSettingInt(maxValue, 1<<30)}
	// 默认禁止访问敏感文件
	policy.DenyPaths = strings.Split(parseSettingString(denyValue, "/etc/shadow,/etc/passwd"), ",")
	return policy
}
