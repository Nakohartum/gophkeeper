package server

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/example/goph-keeper/internal/domain"
	"github.com/example/goph-keeper/internal/store"
)

func TestAPIWorkflow(t *testing.T) {
	repository, err := store.Open(filepath.Join(t.TempDir(), "store.json"))
	if err != nil {
		t.Fatal(err)
	}
	service := httptest.NewServer(New(repository, []byte("01234567890123456789012345678901"), nil).Handler())
	defer service.Close()
	var registration domain.TokenResponse
	status := call(t, service.URL+"/v1/register", http.MethodPost, "", domain.Credentials{Username: "alice", Password: "password1"}, &registration)
	if status != http.StatusCreated || registration.Token == "" {
		t.Fatalf("register status=%d token=%q", status, registration.Token)
	}
	if status = call(t, service.URL+"/v1/register", http.MethodPost, "", domain.Credentials{Username: "alice", Password: "password1"}, nil); status != http.StatusConflict {
		t.Fatalf("duplicate status=%d", status)
	}
	if status = call(t, service.URL+"/v1/login", http.MethodPost, "", domain.Credentials{Username: "alice", Password: "wrongpass"}, nil); status != http.StatusUnauthorized {
		t.Fatalf("bad login status=%d", status)
	}
	var login domain.TokenResponse
	status = call(t, service.URL+"/v1/login", http.MethodPost, "", domain.Credentials{Username: "alice", Password: "password1"}, &login)
	if status != http.StatusOK || login.Token == "" {
		t.Fatalf("login status=%d", status)
	}
	if status = call(t, service.URL+"/v1/items", http.MethodGet, "", nil, nil); status != http.StatusUnauthorized {
		t.Fatalf("anonymous list status=%d", status)
	}
	var item domain.Item
	status = call(t, service.URL+"/v1/items/item-1", http.MethodPut, login.Token, domain.PutItem{Ciphertext: "opaque"}, &item)
	if status != http.StatusOK || item.Version != 1 {
		t.Fatalf("put status=%d item=%#v", status, item)
	}
	if status = call(t, service.URL+"/v1/items/item-1", http.MethodPut, login.Token, domain.PutItem{Ciphertext: "stale"}, nil); status != http.StatusConflict {
		t.Fatalf("conflict status=%d", status)
	}
	var items []domain.Item
	status = call(t, service.URL+"/v1/items", http.MethodGet, login.Token, nil, &items)
	if status != http.StatusOK || len(items) != 1 || items[0].Ciphertext != "opaque" {
		t.Fatalf("list status=%d items=%#v", status, items)
	}
}

func TestValidationAndHealth(t *testing.T) {
	repository, _ := store.Open(filepath.Join(t.TempDir(), "store.json"))
	handler := New(repository, []byte("01234567890123456789012345678901"), nil).Handler()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, "/health", nil))
	if recorder.Code != http.StatusOK {
		t.Fatalf("health status=%d", recorder.Code)
	}
	recorder = httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/v1/register", bytes.NewBufferString("{")))
	if recorder.Code != http.StatusBadRequest {
		t.Fatalf("JSON status=%d", recorder.Code)
	}
	if status := callHandler(handler, "/v1/register", http.MethodPost, "", domain.Credentials{Username: "ab", Password: "short"}); status != http.StatusBadRequest {
		t.Fatalf("validation status=%d", status)
	}
}

func call(t *testing.T, url, method, token string, input, output any) int {
	t.Helper()
	var body bytes.Buffer
	if input != nil {
		_ = json.NewEncoder(&body).Encode(input)
	}
	request, err := http.NewRequest(method, url, &body)
	if err != nil {
		t.Fatal(err)
	}
	request.Header.Set("Content-Type", "application/json")
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	if output != nil {
		_ = json.NewDecoder(response.Body).Decode(output)
	}
	return response.StatusCode
}

func callHandler(handler http.Handler, path, method, token string, input any) int {
	var body bytes.Buffer
	_ = json.NewEncoder(&body).Encode(input)
	request := httptest.NewRequest(method, path, &body)
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, request)
	return recorder.Code
}
