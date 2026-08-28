// Package client provides the remote API client and end-to-end secret encryption.
package client

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"

	"github.com/example/goph-keeper/internal/domain"
	"github.com/example/goph-keeper/internal/security"
)

// HTTPDoer executes HTTP requests.
//
// The standard *http.Client implements HTTPDoer. A small interface keeps API
// independent from a concrete transport and permits deterministic tests.
type HTTPDoer interface {
	Do(request *http.Request) (*http.Response, error)
}

// API communicates with one GophKeeper server.
type API struct {
	baseURL string
	http    HTTPDoer
}

// New creates an API client for baseURL.
func New(baseURL string, transport HTTPDoer) (*API, error) {
	parsed, err := url.Parse(strings.TrimRight(baseURL, "/"))
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") || parsed.Host == "" {
		return nil, errors.New("invalid server URL")
	}
	if transport == nil {
		transport = http.DefaultClient
	}
	return &API{baseURL: parsed.String(), http: transport}, nil
}

var _ HTTPDoer = (*http.Client)(nil)

// Register creates an account and returns a bearer token.
func (a *API) Register(ctx context.Context, credentials domain.Credentials) (string, error) {
	return a.authenticate(ctx, "/v1/register", credentials)
}

// Login authenticates an account and returns a bearer token.
func (a *API) Login(ctx context.Context, credentials domain.Credentials) (string, error) {
	return a.authenticate(ctx, "/v1/login", credentials)
}

func (a *API) authenticate(ctx context.Context, path string, credentials domain.Credentials) (string, error) {
	var response domain.TokenResponse
	if err := a.request(ctx, http.MethodPost, path, "", credentials, &response); err != nil {
		return "", err
	}
	return response.Token, nil
}

// List downloads all encrypted records and tombstones.
func (a *API) List(ctx context.Context, token string) ([]domain.Item, error) {
	var items []domain.Item
	err := a.request(ctx, http.MethodGet, "/v1/items", token, nil, &items)
	return items, err
}

// Put creates, updates, or deletes an encrypted item.
func (a *API) Put(ctx context.Context, token, id string, value domain.PutItem) (domain.Item, error) {
	var item domain.Item
	err := a.request(ctx, http.MethodPut, "/v1/items/"+url.PathEscape(id), token, value, &item)
	return item, err
}

func (a *API) request(ctx context.Context, method, path, token string, input, output any) error {
	var body io.Reader
	if input != nil {
		data, err := json.Marshal(input)
		if err != nil {
			return err
		}
		body = bytes.NewReader(data)
	}
	request, err := http.NewRequestWithContext(ctx, method, a.baseURL+path, body)
	if err != nil {
		return err
	}
	request.Header.Set("Accept", "application/json")
	if input != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if token != "" {
		request.Header.Set("Authorization", "Bearer "+token)
	}
	response, err := a.http.Do(request)
	if err != nil {
		return err
	}
	defer func() { _ = response.Body.Close() }()
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		var apiError domain.ErrorResponse
		if json.NewDecoder(io.LimitReader(response.Body, 1<<20)).Decode(&apiError) == nil && apiError.Error != "" {
			return fmt.Errorf("server returned %d: %s", response.StatusCode, apiError.Error)
		}
		return fmt.Errorf("server returned %s", response.Status)
	}
	if output != nil {
		if err = json.NewDecoder(io.LimitReader(response.Body, 20<<20)).Decode(output); err != nil {
			return fmt.Errorf("decode response: %w", err)
		}
	}
	return nil
}

// SealSecret serializes and encrypts a secret for server storage.
func SealSecret(key []byte, secret domain.Secret) (string, error) {
	data, err := json.Marshal(secret)
	if err != nil {
		return "", err
	}
	return security.Encrypt(key, data)
}

// OpenSecret decrypts and validates an encrypted secret.
func OpenSecret(key []byte, ciphertext string) (domain.Secret, error) {
	data, err := security.Decrypt(key, ciphertext)
	if err != nil {
		return domain.Secret{}, err
	}
	var secret domain.Secret
	if err = json.Unmarshal(data, &secret); err != nil {
		return domain.Secret{}, err
	}
	return secret, nil
}

// NewID returns a cryptographically random item identifier.
func NewID() (string, error) {
	value := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, value); err != nil {
		return "", err
	}
	return hex.EncodeToString(value), nil
}
