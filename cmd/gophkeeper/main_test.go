package main

import (
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/example/goph-keeper/internal/server"
	"github.com/example/goph-keeper/internal/store"
)

func TestCLIWorkflow(t *testing.T) {
	repository, err := store.Open(filepath.Join(t.TempDir(), "server.json"))
	if err != nil {
		t.Fatal(err)
	}
	service := httptest.NewServer(server.New(repository, []byte("01234567890123456789012345678901"), nil).Handler())
	defer service.Close()
	configPath := filepath.Join(t.TempDir(), "client.json")
	t.Setenv("GOPHKEEPER_SERVER", service.URL)
	t.Setenv("GOPHKEEPER_CONFIG", configPath)
	t.Setenv("GOPHKEEPER_PASSWORD", "password1")

	if err = run([]string{"register", "-username", "alice", "-password", "password1"}); err != nil {
		t.Fatal(err)
	}
	if err = run([]string{"login", "-username", "alice", "-password", "password1"}); err != nil {
		t.Fatal(err)
	}
	if err = run([]string{"add", "-type", "credential", "-name", "example", "-data", `{"login":"alice","password":"secret"}`, "-meta", "work"}); err != nil {
		t.Fatal(err)
	}
	cfg, err := loadConfig(configPath)
	if err != nil || len(cfg.Items) != 1 {
		t.Fatalf("config=%#v err=%v", cfg, err)
	}
	id := cfg.Items[0].ID
	for _, args := range [][]string{{"list"}, {"get", id}, {"sync"}, {"delete", id}, {"version"}, nil} {
		if err = run(args); err != nil {
			t.Fatalf("run(%v): %v", args, err)
		}
	}
}

func TestCLIBinaryAndValidation(t *testing.T) {
	repository, _ := store.Open(filepath.Join(t.TempDir(), "server.json"))
	service := httptest.NewServer(server.New(repository, []byte("01234567890123456789012345678901"), nil).Handler())
	defer service.Close()
	configPath := filepath.Join(t.TempDir(), "client.json")
	t.Setenv("GOPHKEEPER_SERVER", service.URL)
	t.Setenv("GOPHKEEPER_CONFIG", configPath)
	t.Setenv("GOPHKEEPER_PASSWORD", "password1")
	if err := run([]string{"register", "-username", "alice", "-password", "password1"}); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(t.TempDir(), "blob.bin")
	if err := os.WriteFile(file, []byte{0, 1, 2}, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := run([]string{"add", "-name", "blob", "-file", file}); err != nil {
		t.Fatal(err)
	}
	for _, args := range [][]string{
		{"unknown"},
		{"get"},
		{"delete"},
		{"add"},
		{"add", "-name", "x", "-type", "unknown"},
		{"add", "-name", "x", "-data", "{"},
	} {
		if err := run(args); err == nil {
			t.Fatalf("expected error for %v", args)
		}
	}
}
