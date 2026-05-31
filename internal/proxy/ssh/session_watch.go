package sshproxy

import (
	"context"
	"sync"
	"time"
)

const sessionFinishPollInterval = 2 * time.Second

func watchSessionFinish(ctx context.Context, api apiClient, sessionID int64, closeFns ...func()) context.CancelFunc {
	watchCtx, cancel := context.WithCancel(ctx)
	var once sync.Once
	closeAll := func() {
		once.Do(func() {
			for _, closeFn := range closeFns {
				if closeFn != nil {
					closeFn()
				}
			}
		})
	}
	go func() {
		ticker := time.NewTicker(sessionFinishPollInterval)
		defer ticker.Stop()
		for {
			select {
			case <-watchCtx.Done():
				return
			case <-ticker.C:
				session, err := api.GetSession(watchCtx, sessionID)
				if err != nil {
					continue
				}
				if session.IsFinished {
					closeAll()
					return
				}
			}
		}
	}()
	return cancel
}
