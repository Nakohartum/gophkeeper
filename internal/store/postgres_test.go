package store

import (
	"errors"
	"testing"
	"time"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/example/goph-keeper/internal/domain"
)

func TestSQLStoreUsers(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	repository := &SQLStore{db: db}
	ctx := t.Context()
	mock.ExpectExec("INSERT INTO users").
		WithArgs(sqlmock.AnyArg(), "Alice", "alice", "hash").
		WillReturnResult(sqlmock.NewResult(0, 1))
	id, err := repository.CreateUser(ctx, "Alice", "hash")
	if err != nil || len(id) != 32 {
		t.Fatalf("CreateUser() id=%q err=%v", id, err)
	}
	mock.ExpectExec("INSERT INTO users").
		WithArgs(sqlmock.AnyArg(), "Alice", "alice", "hash").
		WillReturnError(testSQLStateError("23505"))
	if _, err = repository.CreateUser(ctx, "Alice", "hash"); !errors.Is(err, domain.ErrUsernameTaken) {
		t.Fatalf("duplicate error = %v", err)
	}
	mock.ExpectQuery("SELECT id, password_hash FROM users").
		WithArgs("alice").
		WillReturnRows(sqlmock.NewRows([]string{"id", "password_hash"}).AddRow("user-1", "hash"))
	gotID, hash, err := repository.UserByName(ctx, " ALICE ")
	if err != nil || gotID != "user-1" || hash != "hash" {
		t.Fatalf("UserByName() = %q, %q, %v", gotID, hash, err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestSQLStoreItems(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = db.Close() }()
	repository := &SQLStore{db: db}
	ctx := t.Context()
	now := time.Now().UTC()
	mock.ExpectQuery("SELECT id, ciphertext, version, deleted, updated_at").
		WithArgs("user-1").
		WillReturnRows(sqlmock.NewRows([]string{"id", "ciphertext", "version", "deleted", "updated_at"}).
			AddRow("item-1", "opaque", 1, false, now))
	items, err := repository.List(ctx, "user-1")
	if err != nil || len(items) != 1 || items[0].ID != "item-1" {
		t.Fatalf("List() = %#v, %v", items, err)
	}
	mock.ExpectQuery("INSERT INTO items").
		WithArgs("user-1", "item-2", "cipher", false).
		WillReturnRows(sqlmock.NewRows([]string{"updated_at"}).AddRow(now))
	item, err := repository.Put(ctx, "user-1", "item-2", domain.PutItem{Ciphertext: "cipher"})
	if err != nil || item.Version != 1 || !item.UpdatedAt.Equal(now) {
		t.Fatalf("Put() = %#v, %v", item, err)
	}
	mock.ExpectQuery("INSERT INTO items").
		WithArgs("user-1", "item-2", "stale", false).
		WillReturnRows(sqlmock.NewRows([]string{"updated_at"}))
	mock.ExpectQuery("SELECT id, ciphertext, version, deleted, updated_at").
		WithArgs("user-1", "item-2").
		WillReturnRows(sqlmock.NewRows([]string{"id", "ciphertext", "version", "deleted", "updated_at"}).
			AddRow("item-2", "cipher", 1, false, now))
	current, err := repository.Put(ctx, "user-1", "item-2", domain.PutItem{Ciphertext: "stale"})
	if !errors.Is(err, domain.ErrConflict) || current.Version != 1 {
		t.Fatalf("conflict = %#v, %v", current, err)
	}
	if err = mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}

func TestSQLStoreErrorMapping(t *testing.T) {
	t.Run("missing user", func(t *testing.T) {
		repository, mock := newMockSQLStore(t)
		mock.ExpectQuery("SELECT id, password_hash FROM users").
			WithArgs("missing").
			WillReturnRows(sqlmock.NewRows([]string{"id", "password_hash"}))
		if _, _, err := repository.UserByName(t.Context(), "missing"); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("UserByName() error = %v", err)
		}
	})
	t.Run("list query failure", func(t *testing.T) {
		repository, mock := newMockSQLStore(t)
		mock.ExpectQuery("SELECT id, ciphertext, version, deleted, updated_at").
			WithArgs("user-1").
			WillReturnError(errors.New("connection lost"))
		if _, err := repository.List(t.Context(), "user-1"); err == nil {
			t.Fatal("List() accepted a query failure")
		}
	})
	t.Run("update item", func(t *testing.T) {
		repository, mock := newMockSQLStore(t)
		now := time.Now().UTC()
		mock.ExpectQuery("UPDATE items").
			WithArgs("user-1", "item-1", "new", int64(2), false, int64(1)).
			WillReturnRows(sqlmock.NewRows([]string{"updated_at"}).AddRow(now))
		item, err := repository.Put(t.Context(), "user-1", "item-1", domain.PutItem{
			Ciphertext: "new", Version: 1,
		})
		if err != nil || item.Version != 2 {
			t.Fatalf("Put() = %#v, %v", item, err)
		}
	})
	t.Run("foreign key failure", func(t *testing.T) {
		repository, mock := newMockSQLStore(t)
		mock.ExpectQuery("INSERT INTO items").
			WithArgs("missing", "item-1", "cipher", false).
			WillReturnError(testSQLStateError("23503"))
		if _, err := repository.Put(t.Context(), "missing", "item-1", domain.PutItem{Ciphertext: "cipher"}); !errors.Is(err, domain.ErrNotFound) {
			t.Fatalf("Put() error = %v", err)
		}
	})
}

func newMockSQLStore(t *testing.T) (*SQLStore, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return &SQLStore{db: db}, mock
}

type testSQLStateError string

func (e testSQLStateError) Error() string {
	return string(e)
}

func (e testSQLStateError) SQLState() string {
	return string(e)
}
