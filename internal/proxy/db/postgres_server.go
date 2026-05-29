package dbproxy

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sort"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgproto3"
)

// postgresProxy PostgreSQL 协议代理的核心管理结构体。
// 它持有 API 客户端、连接限流器、超时配置和取消注册表，是整个代理生命周期的主控。
type postgresProxy struct {
	api            apiClient              // API 客户端，用于验证连接令牌和创建/结束会话
	limit          *limiter                // 并发连接数限流器，控制同时代理的最大连接数
	connectTimeout time.Duration           // 连接目标 PostgreSQL 的超时时间
	idleTimeout    time.Duration           // 连接空闲超时时间（读/写无活动时断开）
	cancels        *postgresCancelRegistry // PostgreSQL cancel 请求注册表，记录后端连接信息以转发 cancel
}

// postgresTarget 描述一个已建立的到目标 PostgreSQL 的连接状态。
// 它封装了底层 net.Conn、pgproto3 前端收发器以及连接的元信息，
// 使代理可以透明地在客户端和真实 PG 之间中继消息。
type postgresTarget struct {
	conn              net.Conn             // 通过 pgconn Hijack 获取的原始 TCP 连接，用于双向透明中继
	frontend          *pgproto3.Frontend   // pgproto3 前端收发器，用于向后端 PG 发送和接收 wire protocol 消息
	processID         uint32               // 后端 PG 分配的后端进程 ID，用于 cancel 请求和 BackendKeyData
	secretKey         []byte               // 后端 PG 分配的秘密密钥，配合 processID 完成 cancel 认证
	parameterStatuses map[string]string    // 后端 PG 的参数状态（如 server_version、DateStyle 等），会转发给客户端
	txStatus          byte                 // 当前事务状态字节，用于 ReadyForQuery 消息
}

// newPostgresProxy 创建新的 PostgreSQL 协议代理实例。
// maxConnections 控制并发连接上限，connectTimeout/idleTimeout 分别控制建连和空闲超时。
func newPostgresProxy(api apiClient, maxConnections int, connectTimeout, idleTimeout time.Duration) *postgresProxy {
	return &postgresProxy{
		api:            api,
		limit:          newLimiter(maxConnections),
		connectTimeout: connectTimeout,
		idleTimeout:    idleTimeout,
		cancels:        newPostgresCancelRegistry(connectTimeout),
	}
}

// serve 启动代理的 TCP 监听循环。
// 它在一个独立 goroutine 中不断 Accept 新连接，通过信号量限流后为每个连接启动 handleConn goroutine。
// 主 goroutine 通过 channel 监听 ctx 取消或 Accept 错误来优雅退出。
// 当 ctx 被取消时，主动关闭 listener 以触发 Accept 返回 net.ErrClosed，然后正常返回 nil。
func (p *postgresProxy) serve(ctx context.Context, ln net.Listener) error {
	// errCh 用于将 Accept 循环中的错误传回主 goroutine，缓冲区为 1 避免 goroutine 泄漏
	errCh := make(chan error, 1)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				// Accept 出错（如 listener 关闭），将错误发送给主 goroutine
				errCh <- err
				return
			}
			// 并发限流：如果已达到最大连接数，直接关闭该连接
			if !p.limit.acquire() {
				_ = conn.Close()
				continue
			}
			// 为每个连接启动独立 goroutine 处理，释放限流信号量由 handleConn 生命周期控制
			go func() {
				defer p.limit.release()
				p.handleConn(ctx, conn)
			}()
		}
	}()

	// 等待 ctx 取消或 Accept 出错，二者之一发生则退出
	select {
	case <-ctx.Done():
		// ctx 取消：关闭 listener 促使 Accept 返回错误，然后读取该错误以同步 goroutine 退出
		_ = ln.Close()
		err := <-errCh
		if errors.Is(err, net.ErrClosed) {
			return nil // listener 正常关闭，不算错误
		}
		return err
	case err := <-errCh:
		// Accept 直接出错（如端口占用、系统限制等）
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	}
}

// handleConn 处理单个客户端 PostgreSQL 连接。
// 完整流程：
//  1. 设置连接空闲超时
//  2. 接收并解析客户端 startup 消息（拒绝 SSL/GSS，仅接受纯 startup）
//  3. 从 startup 参数中提取连接令牌并验证
//  4. 创建代理会话（session）
//  5. 打开到目标 PG 的连接并 hijack 获取原始 net.Conn
//  6. 向客户端回复 AuthOK + 参数状态 + BackendKeyData + ReadyForQuery
//  7. 进入双向中继模式，在客户端和目标之间透明转发消息
func (p *postgresProxy) handleConn(parent context.Context, raw net.Conn) {
	defer raw.Close()

	// 创建可取消的子 context，用于控制整个连接生命周期
	ctx, cancel := context.WithCancel(parent)
	defer cancel()

	// 安全获取客户端远程地址，用于审计和会话记录
	remoteAddr := safeRemoteAddr(raw.RemoteAddr())

	// 设置连接的初始截止时间，防止客户端一直不发送 startup 消息
	if p.idleTimeout > 0 {
		_ = raw.SetDeadline(time.Now().Add(p.idleTimeout))
	}

	// 将原始连接封装为 pgproto3 后端收发器（Backend 角色对应代理接收客户端消息）
	client := pgproto3.NewBackend(raw, raw)

	// 阶段 1：接收客户端 startup 消息（拒绝 SSL/GSS，处理 cancel，仅接受纯 startup）
	startup, ok := p.receiveStartup(ctx, raw, client)
	if !ok {
		return
	}

	// 阶段 2：从 startup 参数中提取连接令牌（user 字段作为 token）
	token := postgresStartupToken(startup)
	if token == "" {
		_ = sendPostgresError(client, "28000", "connection token required")
		return
	}

	// 阶段 3：验证连接令牌，获取授权信息（包含目标数据库连接参数）
	auth, err := p.api.VerifyConnectionToken(ctx, token, remoteAddr)
	if err != nil {
		_ = sendPostgresError(client, "28000", "token verification failed")
		return
	}

	// 确保连接令牌对应的协议为 postgres（防止误用 MySQL 等令牌）
	if !isPostgresProtocol(auth.Target.Protocol) {
		_ = sendPostgresError(client, "28000", "connection token protocol is not postgres")
		return
	}

	// 如果授权信息未指定数据库名，使用 startup 消息中客户端请求的 database 参数
	if auth.Account.DBName == "" {
		auth.Account.DBName = startup.Parameters["database"]
	}

	// 阶段 4：创建代理会话记录（用于审计和会话管理）
	session, err := p.api.CreateSession(ctx, sessionInfo{
		UserID:        auth.UserID,
		AssetID:       auth.AssetID,
		AccountID:     auth.AccountID,
		Protocol:      "postgres",
		Type:          "db_proxy",
		ConnectMethod: "postgres_client",
		RemoteAddr:    remoteAddr,
	})
	if err != nil {
		_ = sendPostgresError(client, "58000", "create db session failed")
		return
	}
	// 确保连接结束时标记会话完成（使用 Background context 防止取消影响清理）
	defer func() {
		_ = p.api.FinishSession(context.Background(), session.SessionID)
	}()

	// 阶段 5：打开到目标 PostgreSQL 的连接
	// 使用 pgconn 库建立连接，并通过 Hijack 获取底层 net.Conn 做透明中继
	target, err := p.openTarget(ctx, auth, startup)
	if err != nil {
		_ = sendPostgresError(client, "08006", "connect target postgres failed")
		return
	}
	defer target.close()

	// 将目标连接信息注册到 cancel 注册表
	// 当客户端发送 cancel 请求时，代理可以找到对应的目标连接并转发 cancel
	removeCancel := p.cancels.add(postgresCancelTarget{
		network:   target.conn.RemoteAddr().Network(),
		address:   target.conn.RemoteAddr().String(),
		processID: target.processID,
		secretKey: target.secretKey,
	})
	defer removeCancel()

	// 阶段 6：向客户端发送认证成功消息及连接参数
	// 包括：AuthenticationOk → ParameterStatus(s) → bastion_session_id → BackendKeyData → ReadyForQuery
	if err := p.sendStartupOK(client, target, session.SessionID); err != nil {
		return
	}

	// 阶段 7：进入双向中继模式
	// 创建审计状态记录器，然后启动两个 goroutine 分别在客户端→目标、目标→客户端方向中继消息
	audit := newPostgresAuditState(ctx, p.api, auth.UserID, session.SessionID, remoteAddr)
	p.relay(ctx, raw, client, target, audit)
}

// receiveStartup 实现 PostgreSQL 连接建立阶段的状态机。
// 它循环接收 startup 阶段消息，按协议规范处理：
//   - SSLRequest / GSSEncRequest：代理不支持加密，直接回复拒绝（'N' 字节）
//   - CancelRequest：查找取消注册表并转发 cancel 请求到目标 PG，然后标记连接不继续
//   - StartupMessage：唯一正常接受的消息，返回给调用者继续后续流程
//   - 其他未知消息：返回错误
//
// 返回值：(*pgproto3.StartupMessage, true) 表示成功接收到 startup 消息；
// (nil, false) 表示协商失败或连接不应继续。
func (p *postgresProxy) receiveStartup(ctx context.Context, raw net.Conn, backend *pgproto3.Backend) (*pgproto3.StartupMessage, bool) {
	for {
		// 接收 startup 阶段消息（SSLRequest / GSSEncRequest / CancelRequest / StartupMessage）
		msg, err := backend.ReceiveStartupMessage()
		if err != nil {
			return nil, false
		}
		switch m := msg.(type) {
		case *pgproto3.SSLRequest:
			// 代理不支持 SSL 加密，回复 'N' 拒绝，客户端通常会退回到非加密连接
			if err := writePostgresSSLRefusal(raw); err != nil {
				return nil, false
			}
		case *pgproto3.GSSEncRequest:
			// 代理不支持 GSSAPI 加密，同样回复拒绝
			if err := writePostgresSSLRefusal(raw); err != nil {
				return nil, false
			}
		case *pgproto3.CancelRequest:
			// 取消请求：查找注册表中的目标连接信息，转发 cancel 到目标 PG
			// 此连接到此结束，不需要继续
			_ = p.cancels.forward(ctx, m)
			return nil, false
		case *pgproto3.StartupMessage:
			// 正常连接请求：返回 startup 消息供后续验证和连接使用
			return m, true
		default:
			// 不支持的 startup 消息类型
			_ = sendPostgresError(backend, "08P01", "unsupported postgres startup message")
			return nil, false
		}
	}
}

// openTarget 建立到目标 PostgreSQL 的连接。
// 流程：
//  1. 通过 auth 信息和 authorize 凭证构建 DSN
//  2. 用 pgconn 库连接到目标 PG
//  3. 调用 Hijack 获取底层 net.Conn，使代理可以绕过 pgconn 直接进行透明中继
//  4. 提取连接元信息（PID、SecretKey、参数状态、事务状态）
//
// 注意：Hijack 之后，pgconn 对象不再管理连接生命周期，代理直接通过 net.Conn 进行 I/O。
func (p *postgresProxy) openTarget(ctx context.Context, auth authResult, startup *pgproto3.StartupMessage) (*postgresTarget, error) {
	// 创建带超时的 connect context，防止建连过程无限等待
	connectCtx, cancel := context.WithTimeout(ctx, p.connectTimeout)
	defer cancel()

	// 根据授权信息构建目标 PG 的 DSN 字符串并解析为连接配置
	cfg, err := pgconn.ParseConfig(buildPostgresDSN(auth, p.connectTimeout))
	if err != nil {
		return nil, err
	}

	// 初始化运行时参数表
	if cfg.RuntimeParams == nil {
		cfg.RuntimeParams = make(map[string]string)
	}

	// 将客户端的 startup 参数转发到目标 PG（除 user 和 database 外）
	// user 和 database 由 authorize 凭证决定，不从客户端传入，防止越权
	for key, value := range startup.Parameters {
		switch strings.ToLower(key) {
		case "user", "database":
			continue
		default:
			cfg.RuntimeParams[key] = value
		}
	}

	// 设置 application_name，标记此连接来自 turjmp 代理，便于在目标 PG 中识别
	if cfg.RuntimeParams["application_name"] == "" {
		cfg.RuntimeParams["application_name"] = "turjmp"
	}

	cfg.ConnectTimeout = p.connectTimeout

	// 使用 pgconn 连接到目标 PostgreSQL
	pgConn, err := pgconn.ConnectConfig(connectCtx, cfg)
	if err != nil {
		return nil, err
	}

	// SyncConn 等待连接握手完成（ReadyForQuery），确保连接处于可用状态
	if err := pgConn.SyncConn(connectCtx); err != nil {
		_ = pgConn.Close(context.Background())
		return nil, err
	}

	// Hijack：从 pgconn 中提取底层 net.Conn 和 pgproto3.Frontend
	// 此后代理直接操作原始连接进行透明中继，pgconn 的连接池/重连等功能不再使用
	hijacked, err := pgConn.Hijack()
	if err != nil {
		_ = pgConn.Close(context.Background())
		return nil, err
	}

	// 获取事务状态，默认值为 idle（未在事务中）
	txStatus := hijacked.TxStatus
	if txStatus == 0 {
		txStatus = postgresReadyIdle
	}

	return &postgresTarget{
		conn:              hijacked.Conn,           // 原始 net.Conn，用于透明双向中继
		frontend:          hijacked.Frontend,       // pgproto3 前端收发器，用于 protocol 级别的消息收发
		processID:         hijacked.PID,            // 后端进程 ID
		secretKey:         hijacked.SecretKey,      // 后端秘密密钥
		parameterStatuses: hijacked.ParameterStatuses, // 后端参数状态（server_version 等）
		txStatus:          txStatus,                // 当前事务状态
	}, nil
}

// sendStartupOK 向客户端发送连接建立成功的响应。
// 按照 PostgreSQL wire protocol 规范，startup 阶段成功后的响应序列为：
//   - AuthenticationOk：告知客户端认证成功
//   - ParameterStatus（多个）：同步目标 PG 的运行时参数（如 server_version、DateStyle 等）
//   - bastion_session_id：自定义参数，携带堡垒机会话 ID
//   - BackendKeyData：告知客户端后端进程 ID 和密钥（用于 cancel 请求）
//   - ReadyForQuery：表示连接已就绪，客户端可以开始发送查询
//
// 参数状态按 key 字母顺序排列，保证输出确定性。
func (p *postgresProxy) sendStartupOK(backend *pgproto3.Backend, target *postgresTarget, sessionID int64) error {
	// 1. 发送认证成功消息
	backend.Send(&pgproto3.AuthenticationOk{})

	// 2. 按字母顺序排序并发送所有参数状态（保证输出确定性）
	keys := make([]string, 0, len(target.parameterStatuses))
	for key := range target.parameterStatuses {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	for _, key := range keys {
		backend.Send(&pgproto3.ParameterStatus{Name: key, Value: target.parameterStatuses[key]})
	}

	// 3. 注入堡垒机会话 ID，方便追踪和审计
	backend.Send(&pgproto3.ParameterStatus{Name: "bastion_session_id", Value: fmt.Sprintf("%d", sessionID)})

	// 4. 发送后端进程 ID 和密钥（用于客户端发送 cancel 请求）
	backend.Send(&pgproto3.BackendKeyData{ProcessID: target.processID, SecretKey: target.secretKey})

	// 5. 发送 ReadyForQuery，标志着连接建立完成，客户端可以开始业务查询
	backend.Send(&pgproto3.ReadyForQuery{TxStatus: target.txStatus})

	// Flush 将缓冲的消息一次性写入网络，确保客户端及时收到
	return backend.Flush()
}

// relay 启动双向中继：两个 goroutine 分别在客户端→目标、目标→客户端方向中继消息。
// 任一方向出错或正常终止时，关闭另一个方向并清理连接。
// 这是透明代理的核心：不解析 SQL 语句，不解码查询结果，仅做字节级转发。
//
// 中继的方向：
//   - copyFrontendToTarget：客户端 → 目标 PG（前端发来的查询、参数等）
//   - copyTargetToFrontend：目标 PG → 客户端（查询结果、通知、错误等）
func (p *postgresProxy) relay(ctx context.Context, raw net.Conn, client *pgproto3.Backend, target *postgresTarget, audit *postgresAuditState) {
	// 创建中继专用的 context，任一方向终止时 cancel 通知另一个方向退出
	relayCtx, cancel := context.WithCancel(ctx)
	defer cancel()

	// 错误 channel，两个 goroutine 都会发送结果，取第一个完成者
	errCh := make(chan error, 2)
	go func() {
		errCh <- p.copyFrontendToTarget(relayCtx, raw, client, target, audit)
	}()
	go func() {
		errCh <- p.copyTargetToFrontend(relayCtx, client, target, audit)
	}()

	// 等待任一方向终止（正常结束或出错）
	<-errCh
	// 取消 context 以通知另一个方向终止
	cancel()
	// 强制关闭客户端连接和目标连接，确保资源释放
	_ = raw.Close()
	target.close()
}

// copyFrontendToTarget 单向中继循环：客户端 → 目标 PG。
// 从 pgproto3 Backend（客户端侧）接收消息，通过目标 Frontend 发送到目标 PG。
//
// 终止条件（按优先级）：
//  1. ctx 被取消（relay 中另一方向已终止）
//  2. 接收到 Terminate 消息（客户端主动断开）
//  3. 读取错误（EOF / UnexpectedEOF 视为正常断开，不返回 error）
//  4. 写入目标错误
//
// 每次读取前重置空闲超时，超时时操作会被操作系统中断。
// 审计中间件 observeFrontend 记录客户端发来的消息（仅统计，不解析内容）。
func (p *postgresProxy) copyFrontendToTarget(ctx context.Context, raw net.Conn, client *pgproto3.Backend, target *postgresTarget, audit *postgresAuditState) error {
	for {
		// 每次循环前重置空闲超时计时器，超时时间内无消息则读取会失败
		if p.idleTimeout > 0 {
			_ = raw.SetDeadline(time.Now().Add(p.idleTimeout))
		}
		// 从客户端接收一条 wire protocol 消息
		msg, err := client.Receive()
		if err != nil {
			// EOF / UnexpectedEOF 是客户端正常断开的标志，不视为错误
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return err
		}
		// 审计：记录客户端发送的消息（类型、长度等）
		audit.observeFrontend(msg)

		// 将消息原样转发到目标 PG
		target.frontend.Send(msg)
		if err := target.frontend.Flush(); err != nil {
			return err
		}

		// Terminate 消息：客户端正常断开，退出中继循环
		if _, ok := msg.(*pgproto3.Terminate); ok {
			return nil
		}

		// 非阻塞检查 context 是否已取消（另一方向已终止）
		select {
		case <-ctx.Done():
			return nil
		default:
		}
	}
}

// copyTargetToFrontend 单向中继循环：目标 PG → 客户端。
// 从目标 Frontend 接收消息（查询结果、通知、错误等），通过 pgproto3 Backend 发送给客户端。
//
// 终止条件：
//  1. ctx 被取消（relay 中另一方向已终止）
//  2. 读取错误（EOF / UnexpectedEOF 视为正常断开）
//  3. 写入客户端错误
//
// 审计中间件 observeBackend 记录目标 PG 返回的消息（仅统计，不解析内容）。
// 注意：此方向不设置 SetDeadline，避免影响大结果集的传输。
func (p *postgresProxy) copyTargetToFrontend(ctx context.Context, client *pgproto3.Backend, target *postgresTarget, audit *postgresAuditState) error {
	for {
		// 从目标 PG 接收一条 wire protocol 消息
		msg, err := target.frontend.Receive()
		if err != nil {
			// 正常断开连接
			if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
				return nil
			}
			return err
		}

		// 将消息原样转发给客户端
		client.Send(msg)
		if err := client.Flush(); err != nil {
			return err
		}

		// 审计：记录目标 PG 返回的消息
		audit.observeBackend(msg)

		// 非阻塞检查 context 是否已取消
		select {
		case <-ctx.Done():
			return nil
		default:
		}
	}
}

// close 关闭目标 PostgreSQL 连接。
// 安全忽略 nil receiver 和 nil conn 的情况，可以安全地多次调用。
func (t *postgresTarget) close() {
	if t != nil && t.conn != nil {
		_ = t.conn.Close()
	}
}
