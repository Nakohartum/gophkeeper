package migrations

import (
	"database/sql"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
)

func TestLoad(t *testing.T) {
	items, err := load()
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 2 || items[0].version != 1 || items[1].version != 2 {
		t.Fatalf("load() = %#v", items)
	}
	for _, item := range items {
		if item.name == "" || item.checksum == "" || item.up == "" || item.down == "" {
			t.Fatalf("incomplete migration: %#v", item)
		}
	}
}

func TestUp(t *testing.T) {
	db, mock := newMockDB(t)
	items, _ := load()
	mock.ExpectBegin()
	expectPrepare(mock)
	for _, item := range items {
		mock.ExpectQuery("SELECT checksum FROM schema_migrations").
			WithArgs(item.version).
			WillReturnRows(sqlmock.NewRows([]string{"checksum"}))
		mock.ExpectExec("CREATE TABLE IF NOT EXISTS").
			WillReturnResult(sqlmock.NewResult(0, 0))
		mock.ExpectExec("INSERT INTO schema_migrations").
			WithArgs(item.version, item.name, item.checksum).
			WillReturnResult(sqlmock.NewResult(0, 1))
	}
	mock.ExpectCommit()
	if err := Up(t.Context(), db); err != nil {
		t.Fatal(err)
	}
	assertExpectations(t, mock)
}

func TestUpRejectsChangedMigration(t *testing.T) {
	db, mock := newMockDB(t)
	items, _ := load()
	mock.ExpectBegin()
	expectPrepare(mock)
	mock.ExpectQuery("SELECT checksum FROM schema_migrations").
		WithArgs(items[0].version).
		WillReturnRows(sqlmock.NewRows([]string{"checksum"}).AddRow("changed"))
	mock.ExpectRollback()
	if err := Up(t.Context(), db); err == nil {
		t.Fatal("Up() accepted a changed applied migration")
	}
	assertExpectations(t, mock)
}

func TestDown(t *testing.T) {
	db, mock := newMockDB(t)
	mock.ExpectBegin()
	expectPrepare(mock)
	mock.ExpectQuery("SELECT version FROM schema_migrations").
		WithArgs(2).
		WillReturnRows(sqlmock.NewRows([]string{"version"}).AddRow(2).AddRow(1))
	mock.ExpectExec("DROP TABLE IF EXISTS items").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("DELETE FROM schema_migrations").WithArgs(int64(2)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectExec("DROP TABLE IF EXISTS users").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("DELETE FROM schema_migrations").WithArgs(int64(1)).WillReturnResult(sqlmock.NewResult(0, 1))
	mock.ExpectCommit()
	if err := Down(t.Context(), db, 2); err != nil {
		t.Fatal(err)
	}
	assertExpectations(t, mock)
}

func TestDownValidatesSteps(t *testing.T) {
	if err := Down(t.Context(), nil, 0); err == nil {
		t.Fatal("Down() accepted zero steps")
	}
}

func TestUpRollsBackOnMigrationFailure(t *testing.T) {
	db, mock := newMockDB(t)
	items, _ := load()
	mock.ExpectBegin()
	expectPrepare(mock)
	mock.ExpectQuery("SELECT checksum FROM schema_migrations").
		WithArgs(items[0].version).
		WillReturnRows(sqlmock.NewRows([]string{"checksum"}))
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS").WillReturnError(errors.New("permission denied"))
	mock.ExpectRollback()
	if err := Up(t.Context(), db); err == nil {
		t.Fatal("Up() accepted a migration failure")
	}
	assertExpectations(t, mock)
}

func newMockDB(t *testing.T) (*sql.DB, sqlmock.Sqlmock) {
	t.Helper()
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	return db, mock
}

func expectPrepare(mock sqlmock.Sqlmock) {
	mock.ExpectExec("CREATE TABLE IF NOT EXISTS schema_migrations").WillReturnResult(sqlmock.NewResult(0, 0))
	mock.ExpectExec("SELECT pg_advisory_xact_lock").WithArgs(advisoryLockID).WillReturnResult(sqlmock.NewResult(0, 1))
}

func assertExpectations(t *testing.T, mock sqlmock.Sqlmock) {
	t.Helper()
	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatal(err)
	}
}
