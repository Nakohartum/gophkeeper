// Package migrations applies and rolls back embedded PostgreSQL schema migrations.
package migrations

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"embed"
	"errors"
	"fmt"
	"sort"
	"strconv"
	"strings"
)

//go:embed *.up.sql *.down.sql
var files embed.FS

const advisoryLockID int64 = 0x476f70684b656570

const createHistoryTable = `CREATE TABLE IF NOT EXISTS schema_migrations (
    version BIGINT PRIMARY KEY,
    name TEXT NOT NULL,
    checksum TEXT NOT NULL,
    applied_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
)`

type migration struct {
	version  int64
	name     string
	checksum string
	up       string
	down     string
}

// Up applies every pending migration in version order in one transaction.
// It serializes concurrent runners with a PostgreSQL advisory lock and rejects
// modified migrations that were already applied.
func Up(ctx context.Context, db *sql.DB) error {
	migrations, err := load()
	if err != nil {
		return err
	}
	return inTransaction(ctx, db, func(tx *sql.Tx) error {
		if err := prepare(ctx, tx); err != nil {
			return err
		}
		for _, item := range migrations {
			var checksum string
			err := tx.QueryRowContext(ctx,
				`SELECT checksum FROM schema_migrations WHERE version = $1`, item.version,
			).Scan(&checksum)
			switch {
			case err == nil && checksum != item.checksum:
				return fmt.Errorf("migration %d checksum mismatch", item.version)
			case err == nil:
				continue
			case !errors.Is(err, sql.ErrNoRows):
				return fmt.Errorf("read migration %d state: %w", item.version, err)
			}
			if _, err = tx.ExecContext(ctx, item.up); err != nil {
				return fmt.Errorf("apply migration %d: %w", item.version, err)
			}
			if _, err = tx.ExecContext(ctx,
				`INSERT INTO schema_migrations (version, name, checksum) VALUES ($1, $2, $3)`,
				item.version, item.name, item.checksum,
			); err != nil {
				return fmt.Errorf("record migration %d: %w", item.version, err)
			}
		}
		return nil
	})
}

// Down rolls back up to steps most recently applied migrations.
func Down(ctx context.Context, db *sql.DB, steps int) error {
	if steps < 1 {
		return errors.New("rollback steps must be positive")
	}
	migrations, err := load()
	if err != nil {
		return err
	}
	byVersion := make(map[int64]migration, len(migrations))
	for _, item := range migrations {
		byVersion[item.version] = item
	}
	return inTransaction(ctx, db, func(tx *sql.Tx) error {
		if err := prepare(ctx, tx); err != nil {
			return err
		}
		rows, err := tx.QueryContext(ctx,
			`SELECT version FROM schema_migrations ORDER BY version DESC LIMIT $1`, steps,
		)
		if err != nil {
			return fmt.Errorf("list migrations to roll back: %w", err)
		}
		versions := make([]int64, 0, steps)
		for rows.Next() {
			var version int64
			if err = rows.Scan(&version); err != nil {
				_ = rows.Close()
				return fmt.Errorf("scan migration version: %w", err)
			}
			versions = append(versions, version)
		}
		if err = rows.Close(); err != nil {
			return fmt.Errorf("close migration rows: %w", err)
		}
		if err = rows.Err(); err != nil {
			return fmt.Errorf("iterate migration versions: %w", err)
		}
		for _, version := range versions {
			item, ok := byVersion[version]
			if !ok {
				return fmt.Errorf("missing down migration for version %d", version)
			}
			if _, err = tx.ExecContext(ctx, item.down); err != nil {
				return fmt.Errorf("roll back migration %d: %w", version, err)
			}
			if _, err = tx.ExecContext(ctx,
				`DELETE FROM schema_migrations WHERE version = $1`, version,
			); err != nil {
				return fmt.Errorf("remove migration %d state: %w", version, err)
			}
		}
		return nil
	})
}

func prepare(ctx context.Context, tx *sql.Tx) error {
	if _, err := tx.ExecContext(ctx, createHistoryTable); err != nil {
		return fmt.Errorf("create migration history: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `SELECT pg_advisory_xact_lock($1)`, advisoryLockID); err != nil {
		return fmt.Errorf("lock migrations: %w", err)
	}
	return nil
}

func inTransaction(ctx context.Context, db *sql.DB, operation func(*sql.Tx) error) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("begin migration transaction: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	if err = operation(tx); err != nil {
		return err
	}
	if err = tx.Commit(); err != nil {
		return fmt.Errorf("commit migrations: %w", err)
	}
	return nil
}

func load() ([]migration, error) {
	entries, err := files.ReadDir(".")
	if err != nil {
		return nil, fmt.Errorf("read embedded migrations: %w", err)
	}
	migrations := make([]migration, 0)
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".up.sql") {
			continue
		}
		parts := strings.SplitN(strings.TrimSuffix(entry.Name(), ".up.sql"), "_", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid migration filename %q", entry.Name())
		}
		version, parseErr := strconv.ParseInt(parts[0], 10, 64)
		if parseErr != nil {
			return nil, fmt.Errorf("parse migration version %q: %w", parts[0], parseErr)
		}
		up, readErr := files.ReadFile(entry.Name())
		if readErr != nil {
			return nil, fmt.Errorf("read migration %q: %w", entry.Name(), readErr)
		}
		downName := strings.TrimSuffix(entry.Name(), ".up.sql") + ".down.sql"
		down, readErr := files.ReadFile(downName)
		if readErr != nil {
			return nil, fmt.Errorf("read down migration %q: %w", downName, readErr)
		}
		digest := sha256.Sum256(up)
		migrations = append(migrations, migration{
			version: version, name: parts[1], checksum: fmt.Sprintf("%x", digest),
			up: string(up), down: string(down),
		})
	}
	sort.Slice(migrations, func(i, j int) bool { return migrations[i].version < migrations[j].version })
	for index := 1; index < len(migrations); index++ {
		if migrations[index-1].version == migrations[index].version {
			return nil, fmt.Errorf("duplicate migration version %d", migrations[index].version)
		}
	}
	return migrations, nil
}
