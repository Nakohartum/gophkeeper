package store

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/example/goph-keeper/internal/domain"
)

func TestStoreLifecycleAndPersistence(t *testing.T) {
	path := filepath.Join(t.TempDir(), "nested", "store.json")
	repository, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	id, err := repository.CreateUser(ctx, "Alice", "hash")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = repository.CreateUser(ctx, "alice", "other"); !errors.Is(err, domain.ErrUsernameTaken) {
		t.Fatal("duplicate username accepted")
	}
	foundID, hash, err := repository.UserByName(ctx, " ALICE ")
	if err != nil || foundID != id || hash != "hash" {
		t.Fatalf("user lookup = %q, %q, %v", foundID, hash, err)
	}
	if _, _, err = repository.UserByName(ctx, "missing"); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("missing lookup = %v", err)
	}
	item, err := repository.Put(ctx, id, "one", domain.PutItem{Ciphertext: "cipher"})
	if err != nil || item.Version != 1 {
		t.Fatalf("create = %#v, %v", item, err)
	}
	if _, err = repository.Put(ctx, id, "one", domain.PutItem{Version: 0, Ciphertext: "stale"}); !errors.Is(err, domain.ErrConflict) {
		t.Fatalf("stale put = %v", err)
	}
	item, err = repository.Put(ctx, id, "one", domain.PutItem{Version: 1, Deleted: true})
	if err != nil || item.Version != 2 || !item.Deleted {
		t.Fatalf("delete = %#v, %v", item, err)
	}
	if _, err = repository.Put(ctx, "missing", "one", domain.PutItem{}); !errors.Is(err, domain.ErrNotFound) {
		t.Fatalf("unknown owner = %v", err)
	}
	reopened, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	items, err := reopened.List(ctx, id)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 || items[0].Version != 2 {
		t.Fatalf("reopened items = %#v", items)
	}
}

func TestOpenInvalidJSON(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bad.json")
	if err := os.WriteFile(path, []byte("{"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(path); err == nil {
		t.Fatal("invalid JSON accepted")
	}
}
