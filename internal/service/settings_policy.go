package service

import (
	"encoding/json"
	"strconv"
	"strings"

	"github.com/tursom/turjmp/internal/repository"
)

func settingBool(store *repository.Store, key string, fallback bool) bool {
	setting, err := store.GetSetting(key)
	if err != nil {
		return fallback
	}
	raw := strings.TrimSpace(setting.Value)
	if raw == "" {
		return fallback
	}
	var decoded bool
	if err := json.Unmarshal([]byte(raw), &decoded); err == nil {
		return decoded
	}
	parsed, err := strconv.ParseBool(strings.Trim(raw, `"`))
	if err != nil {
		return fallback
	}
	return parsed
}

func settingInt(store *repository.Store, key string, fallback int) int {
	setting, err := store.GetSetting(key)
	if err != nil {
		return fallback
	}
	raw := strings.TrimSpace(setting.Value)
	if raw == "" {
		return fallback
	}
	var decoded int
	if err := json.Unmarshal([]byte(raw), &decoded); err == nil {
		return decoded
	}
	parsed, err := strconv.Atoi(strings.Trim(raw, `"`))
	if err != nil {
		return fallback
	}
	return parsed
}
