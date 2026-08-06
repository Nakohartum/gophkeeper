package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/example/goph-keeper/internal/domain"
	"github.com/example/goph-keeper/migrations"
	_ "github.com/jackc/pgx/v5/stdlib"
)

// SQLStore persists users and encrypted items in PostgreSQL.
type SQLStore struct {
	db *sql.DB
}

// OpenPostgres connects to PostgreSQL, verifies the connection, and applies
// all pending embedded schema migrations.
func OpenPostgres(ctx context.Context, dsn string) (*SQLStore, error) {
	if strings.TrimSpace(dsn) == "" {
		return nil, errors.New("PostgreSQL DSN is required")
	}
	db, err := sql.Open("pgx", dsn)
	if err != nil {
		return nil, fmt.Errorf("open PostgreSQL: %w", err)
	}
	db.SetMaxOpenConns(20)
	db.SetMaxIdleConns(5)
	db.SetConnMaxLifetime(30 * time.Minute)
	if err = db.PingContext(ctx); err != nil {
		_ = db.Close()
		return nil, fmt.Errorf("ping PostgreSQL: %w", err)
	}
	if err = migrations.Up(ctx, db); err != nil {
		_ = db.Close()
		return nil, err
	}
	return &SQLStore{db: db}, nil
}

// Close releases all PostgreSQL connections.
func (s *SQLStore) Close() error {
	return s.db.Close()
}

// CreateUser persists a new unique user and returns its random identifier.
func (s *SQLStore) CreateUser(ctx context.Context, username, hash string) (string, error) {
	id, err := randomID()
	if err != nil {
		return "", fmt.Errorf("generate user id: %w", err)
	}
	_, err = s.db.ExecContext(ctx,
		`INSERT INTO users (id, username, username_normalized, password_hash)
		 VALUES ($1, $2, $3, $4)`,
		id, username, normalizeUsername(username), hash,
	)
	if err != nil {
		if isUniqueViolation(err) {
			return "", domain.ErrUsernameTaken
		}
		return "", fmt.Errorf("insert user: %w", err)
	}
	return id, nil
}

// UserByName returns an identifier and password verifier for username.
func (s *SQLStore) UserByName(ctx context.Context, username string) (string, string, error) {
	var id, hash string
	err := s.db.QueryRowContext(ctx,
		`SELECT id, password_hash FROM users WHERE username_normalized = $1`,
		normalizeUsername(username),
	).Scan(&id, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		return "", "", domain.ErrNotFound
	}
	if err != nil {
		return "", "", fmt.Errorf("select user: %w", err)
	}
	return id, hash, nil
}

// List returns all encrypted items and deletion tombstones owned by userID.
func (s *SQLStore) List(ctx context.Context, userID string) ([]domain.Item, error) {
	rows, err := s.db.QueryContext(ctx,
		`SELECT id, ciphertext, version, deleted, updated_at
		 FROM items WHERE user_id = $1 ORDER BY updated_at, id`, userID,
	)
	if err != nil {
		return nil, fmt.Errorf("list items: %w", err)
	}
	defer func() { _ = rows.Close() }()
	items := make([]domain.Item, 0)
	for rows.Next() {
		var item domain.Item
		if err = rows.Scan(&item.ID, &item.Ciphertext, &item.Version, &item.Deleted, &item.UpdatedAt); err != nil {
			return nil, fmt.Errorf("scan item: %w", err)
		}
		items = append(items, item)
	}
	if err = rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate items: %w", err)
	}
	return items, nil
}

// Put atomically creates or replaces an item when its expected version matches.
func (s *SQLStore) Put(ctx context.Context, userID, itemID string, request domain.PutItem) (domain.Item, error) {
	next := domain.Item{
		ID:         itemID,
		Ciphertext: request.Ciphertext,
		Version:    request.Version + 1,
		Deleted:    request.Deleted,
	}
	var err error
	if request.Version == 0 {
		err = s.db.QueryRowContext(ctx,
			`INSERT INTO items (user_id, id, ciphertext, version, deleted, updated_at)
			 VALUES ($1, $2, $3, 1, $4, NOW())
			 ON CONFLICT (user_id, id) DO NOTHING
			 RETURNING updated_at`,
			userID, itemID, request.Ciphertext, request.Deleted,
		).Scan(&next.UpdatedAt)
	} else {
		err = s.db.QueryRowContext(ctx,
			`UPDATE items
			 SET ciphertext = $3, version = $4, deleted = $5, updated_at = NOW()
			 WHERE user_id = $1 AND id = $2 AND version = $6
			 RETURNING updated_at`,
			userID, itemID, request.Ciphertext, next.Version, request.Deleted, request.Version,
		).Scan(&next.UpdatedAt)
	}
	if err == nil {
		return next, nil
	}
	if !errors.Is(err, sql.ErrNoRows) {
		if isForeignKeyViolation(err) {
			return domain.Item{}, domain.ErrNotFound
		}
		return domain.Item{}, fmt.Errorf("put item: %w", err)
	}
	current, currentErr := s.item(ctx, userID, itemID)
	if currentErr == nil {
		return current, domain.ErrConflict
	}
	if !errors.Is(currentErr, domain.ErrNotFound) {
		return domain.Item{}, currentErr
	}
	return domain.Item{}, domain.ErrConflict
}

func (s *SQLStore) item(ctx context.Context, userID, itemID string) (domain.Item, error) {
	var item domain.Item
	err := s.db.QueryRowContext(ctx,
		`SELECT id, ciphertext, version, deleted, updated_at
		 FROM items WHERE user_id = $1 AND id = $2`, userID, itemID,
	).Scan(&item.ID, &item.Ciphertext, &item.Version, &item.Deleted, &item.UpdatedAt)
	if errors.Is(err, sql.ErrNoRows) {
		return domain.Item{}, domain.ErrNotFound
	}
	if err != nil {
		return domain.Item{}, fmt.Errorf("select item: %w", err)
	}
	return item, nil
}

func normalizeUsername(username string) string {
	return strings.ToLower(strings.TrimSpace(username))
}

type sqlStateError interface {
	SQLState() string
}

func isUniqueViolation(err error) bool {
	var state sqlStateError
	return errors.As(err, &state) && state.SQLState() == "23505"
}

func isForeignKeyViolation(err error) bool {
	var state sqlStateError
	return errors.As(err, &state) && state.SQLState() == "23503"
}
