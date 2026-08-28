package client

import (
	"context"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/example/goph-keeper/internal/domain"
	"github.com/example/goph-keeper/internal/security"
	"github.com/example/goph-keeper/internal/server"
	"github.com/example/goph-keeper/internal/store"
)

func TestClientWorkflow(t *testing.T) {
	repository, _ := store.Open(filepath.Join(t.TempDir(), "store.json"))
	service := httptest.NewServer(server.New(repository, []byte("01234567890123456789012345678901"), nil).Handler())
	defer service.Close()
	api, err := New(service.URL, service.Client())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	token, err := api.Register(ctx, domain.Credentials{Username: "alice", Password: "password1"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = api.Login(ctx, domain.Credentials{Username: "alice", Password: "password1"}); err != nil {
		t.Fatal(err)
	}
	key := security.VaultKey("alice", "password1")
	secret := domain.Secret{Type: domain.TypeCredential, Name: "site", Data: map[string]string{"login": "a", "password": "b"}, Meta: "work"}
	ciphertext, err := SealSecret(key, secret)
	if err != nil {
		t.Fatal(err)
	}
	id, err := NewID()
	if err != nil || id == "" {
		t.Fatalf("id=%q err=%v", id, err)
	}
	if _, err = api.Put(ctx, token, id, domain.PutItem{Ciphertext: ciphertext}); err != nil {
		t.Fatal(err)
	}
	items, err := api.List(ctx, token)
	if err != nil || len(items) != 1 {
		t.Fatalf("items=%#v err=%v", items, err)
	}
	opened, err := OpenSecret(key, items[0].Ciphertext)
	if err != nil || opened.Name != secret.Name || opened.Data["password"] != "b" {
		t.Fatalf("secret=%#v err=%v", opened, err)
	}
}

func TestNewAndErrors(t *testing.T) {
	for _, raw := range []string{"", "localhost", "ftp://example.com"} {
		if _, err := New(raw, nil); err == nil {
			t.Fatalf("URL accepted: %q", raw)
		}
	}
	if _, err := OpenSecret(make([]byte, 32), "bad"); err == nil {
		t.Fatal("invalid secret accepted")
	}
}
