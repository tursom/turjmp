// Package dbproxy 实现数据库协议代理和 Web 数据库终端。
// 本文件包含 MySQL 协议代理的核心实现：
// TCP 连接接受、MySQL 握手代理、token 认证、目标数据库连接转发、命令循环、SQL 审计。
package dbproxy

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// mysqlProxy 是 MySQL 协议代理的核心结构体。
// 负责监听客户端 MySQL 连接，验证身份后转发到目标 MySQL 数据库。
type mysqlProxy struct {
	api            apiClient         // 后端 API 客户端（token 验证、会话管理、审计）
	limit          *limiter          // 并发连接数限制器
	connectTimeout time.Duration     // 连接目标数据库的超时时间
	idleTimeout    time.Duration     // 客户端连接的空闲超时时间
}

// newMySQLProxy 创建一个新的 MySQL 协议代理实例。
func newMySQLProxy(api apiClient, maxConnections int, connectTimeout, idleTimeout time.Duration) *mysqlProxy {
	return &mysqlProxy{
		api:            api,
		limit:          newLimiter(maxConnections),
		connectTimeout: connectTimeout,
		idleTimeout:    idleTimeout,
	}
}

// serve 是 MySQL 代理的连接接受主循环。
// 在 TCP 监听器上循环 Accept，并为每个连接启动独立的 goroutine 处理。
// 若达到并发连接上限，直接拒绝新连接（关闭 socket）。
// 当 ctx 被取消时，关闭监听器并等待 accept goroutine 退出。
func (p *mysqlProxy) serve(ctx context.Context, ln net.Listener) error {
	errCh := make(chan error, 1)
	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				errCh <- err
				return
			}
			// 并发连接数限制：超过上限直接拒绝
			if !p.limit.acquire() {
				_ = conn.Close()
				continue
			}
			go func() {
				defer p.limit.release()
				p.handleConn(ctx, conn)
			}()
		}
	}()
	select {
	case <-ctx.Done():
		// 收到取消信号，关闭监听器并等待 accept 错误
		_ = ln.Close()
		err := <-errCh
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	case err := <-errCh:
		if errors.Is(err, net.ErrClosed) {
			return nil
		}
		return err
	}
}

// handleConn 处理单个客户端 MySQL 连接的完整代理流程（共 6 步）：
//
//  1. 向客户端发送 MySQL 握手包（writeHandshake）
//  2. 读取客户端握手响应（readMySQLPacket → parseHandshakeResponse）
//  3. 从用户名/密码中提取连接 token（extractConnectionToken）
//  4. 调用后端 API 验证 token 有效性（VerifyConnectionToken）
//  5. 创建审计会话（CreateSession）
//  6. 连接目标 MySQL 数据库（openTarget）
//  7. 发送认证成功 OK 包给客户端（writeOKPacket）
//  8. 进入命令循环（commandLoop），转发客户端 SQL 到目标数据库
//
// 任何步骤失败都会发送 MySQL 错误包（ER_ACCESS_DENIED_ERROR 1045）并关闭连接。
func (p *mysqlProxy) handleConn(parent context.Context, raw net.Conn) {
	defer raw.Close()
	ctx, cancel := context.WithCancel(parent)
	defer cancel()
	remoteAddr := safeRemoteAddr(raw.RemoteAddr())
	// 设置初始空闲超时
	if p.idleTimeout > 0 {
		_ = raw.SetDeadline(time.Now().Add(p.idleTimeout))
	}
	// Step 1: 发送 MySQL 协议握手包（服务器版本、能力标志、认证盐）
	if err := writeHandshake(raw); err != nil {
		return
	}
	// Step 2: 读取客户端握手响应包
	payload, _, err := readMySQLPacket(raw)
	if err != nil {
		return
	}
	hello, err := parseHandshakeResponse(payload)
	if err != nil {
		_ = writeErrorPacket(raw, 2, 1045, err.Error())
		return
	}
	// Step 3: 从用户名/密码中提取连接 token
	token := extractConnectionToken(hello.Username, hello.Password)
	if token == "" {
		_ = writeErrorPacket(raw, 2, 1045, "connection token required")
		return
	}
	// Step 4: 调用后端 API 验证 token
	auth, err := p.api.VerifyConnectionToken(ctx, token, remoteAddr)
	if err != nil {
		_ = writeErrorPacket(raw, 2, 1045, "token verification failed")
		return
	}
	// 确认目标协议是 MySQL
	if strings.ToLower(auth.Target.Protocol) != "mysql" {
		_ = writeErrorPacket(raw, 2, 1045, "connection token protocol is not mysql")
		return
	}
	// Step 5: 在审计系统中创建代理会话记录
	session, err := p.api.CreateSession(ctx, sessionInfo{
		UserID:        auth.UserID,
		AssetID:       auth.AssetID,
		AccountID:     auth.AccountID,
		Protocol:      "mysql",
		Type:          "db_proxy",
		ConnectMethod: "mysql_client",
		RemoteAddr:    remoteAddr,
	})
	if err != nil {
		_ = writeErrorPacket(raw, 2, 1045, "create db session failed")
		return
	}
	// 连接关闭时标记会话结束
	defer func() {
		_ = p.api.FinishSession(context.Background(), session.SessionID)
	}()
	// Step 6: 连接目标 MySQL 数据库
	target, err := p.openTarget(ctx, auth)
	if err != nil {
		_ = writeErrorPacket(raw, 2, 1045, "connect target mysql failed")
		return
	}
	defer target.close()
	// 若客户端指定了默认数据库，切换过去
	if hello.Database != "" {
		_, _ = target.conn.ExecContext(ctx, "USE "+quoteMySQLIdent(hello.Database))
	}
	// Step 7: 发送认证成功 OK 包
	if err := writeOKPacket(raw, 2, 0, 0); err != nil {
		return
	}
	// Step 8: 进入命令循环，转发客户端 SQL 到目标数据库
	p.commandLoop(ctx, raw, target, auth, session, remoteAddr)
}

// mysqlTarget 持有到目标 MySQL 数据库的连接。
// 使用 database/sql 标准库的连接池，但限制为 1 个连接以确保请求有序。
type mysqlTarget struct {
	db   *sql.DB  // 数据库连接池句柄
	conn *sql.Conn // 单个数据库连接
}

// openTarget 连接到目标 MySQL 数据库。
// 使用 go-sql-driver/mysql 驱动，通过 buildMySQLDSN 构建连接字符串。
// 限制连接池大小为 1（确保请求顺序），并通过 PingContext 验证连接可用性。
func (p *mysqlProxy) openTarget(ctx context.Context, auth authResult) (*mysqlTarget, error) {
	connectCtx, cancel := context.WithTimeout(ctx, p.connectTimeout)
	defer cancel()
	db, err := sql.Open("mysql", buildMySQLDSN(auth, p.connectTimeout))
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := db.PingContext(connectCtx); err != nil {
		_ = db.Close()
		return nil, err
	}
	conn, err := db.Conn(connectCtx)
	if err != nil {
		_ = db.Close()
		return nil, err
	}
	return &mysqlTarget{db: db, conn: conn}, nil
}

// close 关闭目标数据库连接（先关闭连接，再关闭连接池）。
func (t *mysqlTarget) close() {
	if t.conn != nil {
		_ = t.conn.Close()
	}
	if t.db != nil {
		_ = t.db.Close()
	}
}

// commandLoop 是代理的命令转发循环。
// 从客户端读取 MySQL 命令包，根据命令类型进行路由处理。
// 支持的 6 种命令类型（mysqlCom*）：
//
//  mysqlComQuit (0x01)    — 客户端断开连接，退出循环
//  mysqlComPing (0x0e)    — 心跳检测，返回 OK 包
//  mysqlComInitDB (0x02)  — 切换数据库（USE dbname），转发到目标并审计
//  mysqlComQuery (0x03)   — SQL 查询，转发到 handleQuery 进行结果集处理
//  mysqlComStmtPrepare (0x16) — 预处理语句准备（暂不支持，返回错误 1295）
//  mysqlComStmtExecute (0x17) — 预处理语句执行（暂不支持，返回错误 1295）
//  mysqlComStmtClose  (0x19)  — 关闭预处理语句（暂不支持，返回错误 1295）
//  其他                          — 不支持的命令（返回错误 1064）
func (p *mysqlProxy) commandLoop(ctx context.Context, client net.Conn, target *mysqlTarget, auth authResult, session sessionInfo, remoteAddr string) {
	for {
		// 每次循环刷新空闲超时计时器
		if p.idleTimeout > 0 {
			_ = client.SetDeadline(time.Now().Add(p.idleTimeout))
		}
		payload, _, err := readMySQLPacket(client)
		if err != nil {
			if !errors.Is(err, io.EOF) {
				return
			}
			return
		}
		if len(payload) == 0 {
			_ = writeErrorPacket(client, 1, 1064, "empty mysql command")
			continue
		}
		// payload[0] 为 MySQL 命令类型字节
		switch payload[0] {
		case mysqlComQuit:
			// 客户端主动断开
			return
		case mysqlComPing:
			// 心跳响应
			_ = writeOKPacket(client, 1, 0, 0)
		case mysqlComInitDB:
			// 切换数据库命令：提取数据库名，转发 USE 语句
			dbName := string(payload[1:])
			err := p.execNoResult(ctx, client, target, "USE "+quoteMySQLIdent(dbName))
			p.audit(ctx, auth.UserID, session.SessionID, remoteAddr, "USE "+dbName, 0, err, 0)
		case mysqlComQuery:
			// SQL 查询命令：解析 SQL 文本并转发
			query := string(payload[1:])
			p.handleQuery(ctx, client, target, auth, session, remoteAddr, query)
		case mysqlComStmtPrepare, mysqlComStmtExecute, mysqlComStmtClose:
			// 预处理语句暂不支持（MySQL 错误码 1295: ER_UNSUPPORTED_PS）
			_ = writeErrorPacket(client, 1, 1295, "prepared statements are not supported by this proxy yet")
		default:
			// 未知命令
			_ = writeErrorPacket(client, 1, 1064, fmt.Sprintf("unsupported mysql command 0x%x", payload[0]))
		}
	}
}

// handleQuery 处理一个 SQL 查询命令。
// 区分两种 SQL 类型：
//   - 结果集查询（SELECT、SHOW、DESCRIBE 等）：通过 queryContext 执行并调用 writeResultSet 序列化结果
//   - 非结果集命令（INSERT、UPDATE、DELETE、DDL 等）：通过 execNoResult 执行，自动发送 OK 包
//
// 空查询直接返回 OK 包。
// 无论成功或失败，最终都会记录审计日志。
func (p *mysqlProxy) handleQuery(ctx context.Context, client net.Conn, target *mysqlTarget, auth authResult, session sessionInfo, remoteAddr, query string) {
	start := time.Now()
	var rowsAffected int64
	var err error
	// 空查询直接返回 OK
	if strings.TrimSpace(query) == "" {
		err = writeOKPacket(client, 1, 0, 0)
		p.audit(ctx, auth.UserID, session.SessionID, remoteAddr, query, rowsAffected, err, time.Since(start))
		return
	}
	if isResultQuery(query) {
		// 结果集查询：执行 → 序列化结果集 → 关闭 rows
		var rows *sql.Rows
		rows, err = target.conn.QueryContext(ctx, query)
		if err == nil {
			rowsAffected, err = writeResultSet(client, rows)
			_ = rows.Close()
		}
	} else {
		// 非结果集查询：执行 → OK 包已在 execNoResult 中发送
		err = p.execNoResult(ctx, client, target, query)
		if err == nil {
			// execNoResult 已发送 OK 包；影响行数标记为 -1（审计详情需另外获取）
			rowsAffected = -1
		}
	}
	// 若出错，发送错误包给客户端
	if err != nil {
		_ = writeErrorPacket(client, 1, 1105, err.Error())
	}
	p.audit(ctx, auth.UserID, session.SessionID, remoteAddr, query, rowsAffected, err, time.Since(start))
}

// execNoResult 执行一个不返回结果集的 SQL 命令（INSERT/UPDATE/DELETE/DDL 等）。
// 执行成功后自动发送 OK 包（包含 affected_rows 和 last_insert_id）。
func (p *mysqlProxy) execNoResult(ctx context.Context, client net.Conn, target *mysqlTarget, query string) error {
	res, err := target.conn.ExecContext(ctx, query)
	if err != nil {
		return err
	}
	affected, _ := res.RowsAffected()
	lastID, _ := res.LastInsertId()
	return writeOKPacket(client, 1, strconvUint64(affected), strconvUint64(lastID))
}

// audit 向后端 API 提交一条 SQL 审计日志。
// duration 传入 0 时自动设为 1ms（防止零值）。
func (p *mysqlProxy) audit(ctx context.Context, userID, sessionID int64, remoteAddr, query string, rowsAffected int64, err error, duration time.Duration) {
	if duration == 0 {
		duration = time.Millisecond
	}
	detail := newSQLAuditDetail(sessionID, "mysql", query, duration, rowsAffected, err)
	_ = p.api.Audit(ctx, userID, "db.query", "mysql", remoteAddr, detail)
}
