package domain

import "errors"

var (
	// ErrConflict indicates an optimistic-lock version conflict.
	ErrConflict = errors.New("item version conflict")
	// ErrNotFound indicates that an entity does not exist.
	ErrNotFound = errors.New("not found")
	// ErrUsernameTaken indicates that a normalized username is already registered.
	ErrUsernameTaken = errors.New("username already exists")
)
