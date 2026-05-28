package service

import (
	"time"

	"github.com/tursom/turjmp/internal/domain"
	"github.com/tursom/turjmp/internal/repository"
)

type SessionService struct {
	store *repository.Store
}

func NewSessionService(store *repository.Store) *SessionService {
	return &SessionService{store: store}
}

func (s *SessionService) List() ([]domain.Session, error) {
	return s.store.ListSessions()
}

func (s *SessionService) Get(id int64) (domain.Session, error) {
	return s.store.GetSession(id)
}

func (s *SessionService) Create(sess domain.Session) (domain.Session, error) {
	if sess.Type == "" {
		sess.Type = "normal"
	}
	if sess.LoginFrom == "" {
		sess.LoginFrom = "WT"
	}
	return sess, s.store.CreateSession(&sess)
}

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
