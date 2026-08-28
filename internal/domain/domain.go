// Package domain contains the data exchanged by GophKeeper components.
package domain

import "time"

// ItemType identifies the kind of secret stored in an item.
type ItemType string

const (
	// TypeCredential is a login/password pair.
	TypeCredential ItemType = "credential"
	// TypeText is arbitrary text.
	TypeText ItemType = "text"
	// TypeBinary is arbitrary binary data.
	TypeBinary ItemType = "binary"
	// TypeCard is payment-card data.
	TypeCard ItemType = "card"
)

// Secret is the plaintext representation used only on an authenticated client.
type Secret struct {
	Type ItemType          `json:"type"`
	Name string            `json:"name"`
	Data map[string]string `json:"data"`
	Meta string            `json:"meta,omitempty"`
}

// Item is an opaque encrypted value stored by the server.
type Item struct {
	ID         string    `json:"id"`
	Ciphertext string    `json:"ciphertext,omitempty"`
	Version    int64     `json:"version"`
	Deleted    bool      `json:"deleted,omitempty"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// PutItem is an optimistic-locking request to create, update, or delete an item.
type PutItem struct {
	Ciphertext string `json:"ciphertext,omitempty"`
	Version    int64  `json:"version"`
	Deleted    bool   `json:"deleted,omitempty"`
}

// Credentials contains user registration or login credentials.
type Credentials struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

// TokenResponse is returned after successful registration or login.
type TokenResponse struct {
	Token string `json:"token"`
}

// ErrorResponse is the common JSON error body.
type ErrorResponse struct {
	Error string `json:"error"`
}
