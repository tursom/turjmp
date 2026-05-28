package domain

import "errors"

var (
	ErrNotFound        = errors.New("not found")
	ErrUnauthorized    = errors.New("unauthorized")
	ErrForbidden       = errors.New("forbidden")
	ErrInvalidArgument = errors.New("invalid argument")
	ErrConflict        = errors.New("conflict")
)
