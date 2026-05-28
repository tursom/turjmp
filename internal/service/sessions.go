// Package service 提供业务逻辑层，位于 API 处理器与数据仓库之间，负责会话生命周期管理、录屏路径记录、会话结束状态标记等核心业务流程的编排与验证。
package service

import (
	"time"

	"github.com/tursom/turjmp/internal/domain"
	"github.com/tursom/turjmp/internal/repository"
)

// SessionService 会话管理服务，封装会话的 CRUD 操作，管理连接会话的创建、完成、录屏路径记录等业务逻辑。
type SessionService struct {
	store *repository.Store
}

// NewSessionService 创建 SessionService 实例，注入存储层。
func NewSessionService(store *repository.Store) *SessionService {
	return &SessionService{store: store}
}

// List 获取系统中所有连接会话的列表。
func (s *SessionService) List() ([]domain.Session, error) {
	return s.store.ListSessions()
}

// Get 根据 ID 获取单个会话的详细信息。
func (s *SessionService) Get(id int64) (domain.Session, error) {
	return s.store.GetSession(id)
}

// Create 创建新会话记录。流程：若未指定会话类型则默认设为 "normal" → 若未指定登录来源则默认设为 "WT"（Web Terminal）→ 创建会话记录。
// 会话记录用于审计追踪，记录谁在什么时间连接到哪台资产。
func (s *SessionService) Create(sess domain.Session) (domain.Session, error) {
	if sess.Type == "" {
		sess.Type = "normal"
	}
	if sess.LoginFrom == "" {
		sess.LoginFrom = "WT"
	}
	return sess, s.store.CreateSession(&sess)
}

// Finish 标记指定会话为已完成。流程：查找会话 → 设置 IsFinished 为 true → 设置 DateEnd 为当前时间 → 记录录屏文件路径 → 更新会话记录。
func (s *SessionService) Finish(id int64, recordingPath string) (domain.Session, error) {
	sess, err := s.store.GetSession(id)
	if err != nil {
		return domain.Session{}, err
	}
	sess.IsFinished = true
	sess.DateEnd = repository.NowPtr()
	sess.RecordingPath = recordingPath
	return sess, s.store.UpdateSession(&sess)
}

// Update 更新会话的完成状态和录屏路径。流程：查找会话 → 设置 IsFinished → 若标记为 finished 且 DateEnd 为空则自动填充当前 UTC 时间 → 若传入了录屏路径则覆盖 → 更新会话记录。
// 相比 Finish 方法，Update 更加灵活：可同时设置完成状态和录屏路径，且仅在标记完成时才自动填充结束时间。
func (s *SessionService) Update(id int64, finished bool, recordingPath string) (domain.Session, error) {
	sess, err := s.store.GetSession(id)
	if err != nil {
		return domain.Session{}, err
	}
	sess.IsFinished = finished
	if finished && sess.DateEnd == nil {
		now := time.Now().UTC()
		sess.DateEnd = &now
	}
	if recordingPath != "" {
		sess.RecordingPath = recordingPath
	}
	return sess, s.store.UpdateSession(&sess)
}
