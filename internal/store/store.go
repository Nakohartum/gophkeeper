// Package store provides the persistent server-side repository.
package store

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/example/goph-keeper/internal/domain"
)

// ErrConflict indicates an optimistic-lock version conflict.
var ErrConflict = errors.New("item version conflict")

// ErrNotFound indicates that an entity does not exist.
var ErrNotFound = errors.New("not found")

type user struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Hash     string `json:"hash"`
}

type state struct {
	Users map[string]user                   `json:"users"`
	Items map[string]map[string]domain.Item `json:"items"`
}

// FileStore is a concurrency-safe JSON repository intended for a single server process.
type FileStore struct {
	mu    sync.RWMutex
	path  string
	state state
}

// Open loads or creates a repository stored at path.
func Open(path string) (*FileStore, error) {
	s := &FileStore{path: path, state: state{Users: map[string]user{}, Items: map[string]map[string]domain.Item{}}}
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return nil, err
	}
	if err = json.Unmarshal(data, &s.state); err != nil {
		return nil, fmt.Errorf("decode store: %w", err)
	}
	if s.state.Users == nil {
		s.state.Users = map[string]user{}
	}
	if s.state.Items == nil {
		s.state.Items = map[string]map[string]domain.Item{}
	}
	return s, nil
}

// CreateUser persists a new unique user and returns its identifier.
func (s *FileStore) CreateUser(username, hash string) (string, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := strings.ToLower(strings.TrimSpace(username))
	if _, exists := s.state.Users[key]; exists {
		return "", errors.New("username already exists")
	}
	id := fmt.Sprintf("u-%d", time.Now().UnixNano())
	s.state.Users[key] = user{ID: id, Username: username, Hash: hash}
	s.state.Items[id] = map[string]domain.Item{}
	if err := s.saveLocked(); err != nil {
		delete(s.state.Users, key)
		delete(s.state.Items, id)
		return "", err
	}
	return id, nil
}

// UserByName returns an identifier and password verifier for username.
func (s *FileStore) UserByName(username string) (string, string, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	u, ok := s.state.Users[strings.ToLower(strings.TrimSpace(username))]
	if !ok {
		return "", "", ErrNotFound
	}
	return u.ID, u.Hash, nil
}

// List returns all encrypted items, including deletion tombstones, owned by userID.
func (s *FileStore) List(userID string) []domain.Item {
	s.mu.RLock()
	defer s.mu.RUnlock()
	items := s.state.Items[userID]
	result := make([]domain.Item, 0, len(items))
	for _, item := range items {
		result = append(result, item)
	}
	return result
}

// Put atomically creates or replaces an item when its expected version matches.
func (s *FileStore) Put(userID, itemID string, request domain.PutItem) (domain.Item, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	items, ok := s.state.Items[userID]
	if !ok {
		return domain.Item{}, ErrNotFound
	}
	current, exists := items[itemID]
	if (!exists && request.Version != 0) || (exists && request.Version != current.Version) {
		return current, ErrConflict
	}
	next := domain.Item{
		ID: itemID, Ciphertext: request.Ciphertext, Deleted: request.Deleted,
		Version: request.Version + 1, UpdatedAt: time.Now().UTC(),
	}
	items[itemID] = next
	if err := s.saveLocked(); err != nil {
		if exists {
			items[itemID] = current
		} else {
			delete(items, itemID)
		}
		return domain.Item{}, err
	}
	return next, nil
}

func (s *FileStore) saveLocked() error {
	data, err := json.MarshalIndent(s.state, "", "  ")
	if err != nil {
		return err
	}
	if err = os.MkdirAll(filepath.Dir(s.path), 0o700); err != nil {
		return err
	}
	tmp := s.path + ".tmp"
	if err = os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err = os.Rename(tmp, s.path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}
