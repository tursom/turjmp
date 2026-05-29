package dbproxy

import (
	"context"
	"sync"
	"time"

	"github.com/jackc/pgx/v5/pgproto3"
)

// postgresAuditEvent 表示一条待审计的 SQL 事件。
// 每条事件记录了要审计的 SQL 文本和执行开始时间。
type postgresAuditEvent struct {
	// query 是待审计的 SQL 语句文本
	query string
	// start 是 SQL 开始执行的时刻
	start time.Time
}

// postgresAuditState 是 PostgreSQL 扩展查询协议的审计状态机。
//
// PostgreSQL 扩展查询协议将一条 SQL 的生命周期拆分为多个阶段：
//
//	Parse（解析：给 SQL 命名）→ Bind（绑定：将命名语句绑定到 portal）→ Execute（执行 portal）
//	→ CommandComplete（成功） 或 ErrorResponse（失败）
//
// 代理只能观察到这些协议消息，无法直接拿到完整 SQL，因此审计状态机需要：
//   - prepared 映射：记录 Parse 阶段注册的 语句名 → SQL 文本
//   - portals 映射：记录 Bind 阶段注册的 portal名 → 对应 SQL 文本
//   - pending 队列：按 Execute 顺序存放待审计事件（FIFO）
//
// 当 Execute 消息到达时，通过 portal → 语句 → SQL 链路解析出实际 SQL 并加入 pending。
// 当 CommandComplete 或 ErrorResponse 到达时，从队列头部取出事件完成审计（服务端按序返回）。
type postgresAuditState struct {
	// mu 保护以下所有字段的并发访问
	mu sync.Mutex

	// api 是用于写入审计记录的 API 客户端
	api apiClient
	// ctx 是上下文，控制审计写入请求的生命周期
	ctx context.Context
	// userID 是发起操作的用户 ID
	userID int64
	// sessionID 是当前数据库会话 ID
	sessionID int64
	// remoteAddr 是客户端的远程地址
	remoteAddr string

	// prepared 映射：语句名 → SQL 文本
	// Parse 消息中 Name 为键，Query 为值。
	// 当 Name 为空字符串时表示匿名语句，Execute 会fallback 到这里。
	prepared map[string]string
	// portals 映射：portal 名 → SQL 文本
	// Bind 消息将语句绑定到 portal 时写入。
	portals map[string]string
	// pending 是待审计事件的 FIFO 队列
	// 每个 Execute 调用一次 beginLocked 追加到尾部，
	// 每个 CommandComplete/ErrorResponse 调用 finishNext 从头部取出。
	pending []*postgresAuditEvent
}

// newPostgresAuditState 创建并初始化一个 PostgreSQL 审计状态机实例。
//
// 参数：
//   - ctx:  上下文
//   - api:  审计 API 客户端
//   - userID: 用户 ID
//   - sessionID: 会话 ID
//   - remoteAddr: 客户端地址
//
// 返回初始化后的审计状态机，其 prepared 和 portals 映射已初始化。
func newPostgresAuditState(ctx context.Context, api apiClient, userID, sessionID int64, remoteAddr string) *postgresAuditState {
	return &postgresAuditState{
		api:        api,
		ctx:        ctx,
		userID:     userID,
		sessionID:  sessionID,
		remoteAddr: remoteAddr,
		prepared:   make(map[string]string),
		portals:    make(map[string]string),
	}
}

// observeFrontend 观察客户端发来的前端消息，跟踪 SQL 的解析和绑定过程。
//
// 根据 PostgreSQL 扩展查询协议处理以下消息类型：
//
//	Query:        简单查询协议（一次性发送完整 SQL），直接加入待审计队列
//	Parse:        注册 语句名 → SQL 文本 的映射到 prepared
//	Bind:         将语句绑定到 portal，建立 portal → SQL 的映射到 portals
//	Execute:      通过 portal → SQL 链路解析出实际 SQL 并加入待审计队列
//	Close:        清理 prepared 或 portals 中已关闭的资源
//
// 该方法在 mu 锁保护下执行，保证并发安全。
func (s *postgresAuditState) observeFrontend(msg pgproto3.FrontendMessage) {
	s.mu.Lock()
	defer s.mu.Unlock()

	switch m := msg.(type) {
	case *pgproto3.Query:
		// 简单查询协议：消息中直接包含完整 SQL，直接开始审计
		s.beginLocked(m.String)
	case *pgproto3.Parse:
		// Parse 阶段：注册语句名到 SQL 的映射
		// m.Name 是客户端给语句起的名字，m.Query 是原始 SQL 文本
		s.prepared[m.Name] = m.Query
	case *pgproto3.Bind:
		// Bind 阶段：将已解析的语句绑定到 portal，建立 portal → SQL 映射
		// m.PreparedStatement 是要绑定的语句名（对应 Parse 中的 Name）
		// m.DestinationPortal 是新创建的 portal 名
		query := s.prepared[m.PreparedStatement]
		if query != "" {
			// 只有已知的 prepared 语句才写入 portals 映射
			s.portals[m.DestinationPortal] = query
		}
	case *pgproto3.Execute:
		// Execute 阶段：执行 portal，需要解析出实际 SQL
		// 优先从 portals 中按 portal 名查找 SQL
		query := s.portals[m.Portal]
		if query == "" {
			// fallback：如果 portals 中没有，尝试匿名 prepared 语句（Name 为空字符串）
			query = s.prepared[""]
		}
		if query != "" {
			// 解析出 SQL 后加入待审计队列
			s.beginLocked(query)
		}
	case *pgproto3.Close:
		// Close 阶段：清理不再需要的资源
		switch m.ObjectType {
		case 'S':
			// 关闭语句（Statement），从 prepared 映射中移除
			delete(s.prepared, m.Name)
		case 'P':
			// 关闭 portal，从 portals 映射中移除
			delete(s.portals, m.Name)
		}
	}
}

// observeBackend 观察服务端返回的后端消息，完成审计记录的收尾工作。
//
// 处理以下消息类型：
//
//	CommandComplete:  SQL 成功执行完毕，从队列取出事件并记录审计（含影响行数）
//	ErrorResponse:    SQL 执行失败，从队列取出事件并记录审计（含错误信息）
//	ReadyForQuery:    服务端就绪，清空剩余未完成的事件（隐式事务提交场景）
func (s *postgresAuditState) observeBackend(msg pgproto3.BackendMessage) {
	switch m := msg.(type) {
	case *pgproto3.CommandComplete:
		// SQL 成功：解析影响行数，无错误
		s.finishNext(parsePostgresRowsAffected(m.CommandTag), nil)
	case *pgproto3.ErrorResponse:
		// SQL 失败：影响行数为 0，携带错误信息
		s.finishNext(0, postgresError(m))
	case *pgproto3.ReadyForQuery:
		// 服务端就绪：清空所有未完成的审计事件（隐式事务提交时可能遗留）
		s.flushPending()
	}
}

// beginLocked 在锁保护下向待审计队列尾部追加一条新的审计事件。
//
// 调用方必须已持有 s.mu 锁。该方法记录当前时间作为 SQL 开始时间。
func (s *postgresAuditState) beginLocked(query string) {
	s.pending = append(s.pending, &postgresAuditEvent{
		query: query,
		start: time.Now(),
	})
}

// finishNext 从待审计队列头部取出一个事件并完成审计。
//
// 由于 PostgreSQL 服务端按顺序返回结果，因此采用 FIFO 策略：
// 队列头部的事件对应最先收到的后端响应。
//
// 如果队列为空（异常情况），直接返回不做任何操作。
func (s *postgresAuditState) finishNext(rowsAffected int64, err error) {
	s.mu.Lock()
	if len(s.pending) == 0 {
		// 队列为空，没有可审计的事件（可能是协议消息乱序）
		s.mu.Unlock()
		return
	}
	// 从队列头部取出事件（FIFO：先进先出）
	event := s.pending[0]
	// 将后续元素前移一位，并清理尾部引用以帮助 GC
	copy(s.pending, s.pending[1:])
	s.pending[len(s.pending)-1] = nil
	s.pending = s.pending[:len(s.pending)-1]
	s.mu.Unlock()

	// 锁释放后执行审计写入，避免锁持有时间过长
	s.audit(event, rowsAffected, err)
}

// flushPending 清空所有未完成的审计事件，在 ReadyForQuery 时调用。
//
// 场景：隐式事务提交或连接重置时，服务端发送 ReadyForQuery 表示之前
// 所有操作已结束。此时可能有尚未匹配到 CommandComplete/ErrorResponse 的
// 事件残留，需要全部审计写入。
//
// 所有事件都被标记为影响行数 0 且无错误（中性审计）。
func (s *postgresAuditState) flushPending() {
	var events []*postgresAuditEvent
	s.mu.Lock()
	// 取出所有待处理事件并清空队列
	events = append(events, s.pending...)
	s.pending = nil
	s.mu.Unlock()

	// 逐条审计写入
	for _, event := range events {
		s.audit(event, 0, nil)
	}
}

// audit 执行最终审计写入：计算 SQL 耗时、构造审计详情并调用 API 写入。
//
// 参数：
//   - event:        待审计的事件
//   - rowsAffected: 影响行数（成功时 >0，失败时为 0）
//   - err:          错误信息（成功时为 nil）
//
// 耗时计算使用 time.Since，最小值为 1ms 避免零值使日志过滤失效。
func (s *postgresAuditState) audit(event *postgresAuditEvent, rowsAffected int64, err error) {
	if event == nil {
		return
	}
	// 计算 SQL 执行耗时
	duration := time.Since(event.start)
	if duration <= 0 {
		// 防御性处理：确保最小耗时为 1ms
		duration = time.Millisecond
	}
	// 构造审计详情并异步写入
	detail := newSQLAuditDetail(s.sessionID, "postgres", event.query, duration, rowsAffected, err)
	_ = s.api.Audit(s.ctx, s.userID, "db.query", "postgres", s.remoteAddr, detail)
}
