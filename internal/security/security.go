// Package security implements password hashing, bearer tokens, and client-side encryption.
package security

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"
)

const passwordRounds = 120_000

// PasswordHash creates a salted, computationally expensive password verifier.
func PasswordHash(password string) (string, error) {
	salt := make([]byte, 16)
	if _, err := io.ReadFull(rand.Reader, salt); err != nil {
		return "", err
	}
	key := derive([]byte(password), salt, passwordRounds, 32)
	return fmt.Sprintf("pbkdf2-sha256$%d$%s$%s", passwordRounds,
		base64.RawStdEncoding.EncodeToString(salt), base64.RawStdEncoding.EncodeToString(key)), nil
}

// CheckPassword reports whether password matches an encoded verifier.
func CheckPassword(password, encoded string) bool {
	parts := strings.Split(encoded, "$")
	if len(parts) != 4 || parts[0] != "pbkdf2-sha256" {
		return false
	}
	rounds, err := strconv.Atoi(parts[1])
	salt, errSalt := base64.RawStdEncoding.DecodeString(parts[2])
	want, errHash := base64.RawStdEncoding.DecodeString(parts[3])
	if err != nil || errSalt != nil || errHash != nil || rounds < 10_000 || len(want) == 0 {
		return false
	}
	got := derive([]byte(password), salt, rounds, len(want))
	return subtle.ConstantTimeCompare(got, want) == 1
}

// VaultKey derives a stable client encryption key from user credentials.
func VaultKey(username, password string) []byte {
	salt := sha256.Sum256([]byte("gophkeeper-v1:" + strings.ToLower(username)))
	return derive([]byte(password), salt[:], passwordRounds, 32)
}

func derive(password, salt []byte, rounds, size int) []byte {
	result := make([]byte, 0, size)
	for block := uint32(1); len(result) < size; block++ {
		mac := hmac.New(sha256.New, password)
		_, _ = mac.Write(salt)
		var counter [4]byte
		binary.BigEndian.PutUint32(counter[:], block)
		_, _ = mac.Write(counter[:])
		u := mac.Sum(nil)
		t := append([]byte(nil), u...)
		for i := 1; i < rounds; i++ {
			mac = hmac.New(sha256.New, password)
			_, _ = mac.Write(u)
			u = mac.Sum(nil)
			for j := range t {
				t[j] ^= u[j]
			}
		}
		result = append(result, t...)
	}
	return result[:size]
}

// Encrypt seals plaintext with AES-256-GCM and returns base64 text.
func Encrypt(key, plaintext []byte) (string, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err = io.ReadFull(rand.Reader, nonce); err != nil {
		return "", err
	}
	sealed := gcm.Seal(nonce, nonce, plaintext, nil)
	return base64.RawStdEncoding.EncodeToString(sealed), nil
}

// Decrypt authenticates and opens base64-encoded AES-GCM ciphertext.
func Decrypt(key []byte, encoded string) ([]byte, error) {
	raw, err := base64.RawStdEncoding.DecodeString(encoded)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	if len(raw) < gcm.NonceSize() {
		return nil, errors.New("ciphertext is too short")
	}
	return gcm.Open(nil, raw[:gcm.NonceSize()], raw[gcm.NonceSize():], nil)
}

type claims struct {
	UserID string `json:"sub"`
	Expiry int64  `json:"exp"`
}

// IssueToken creates a signed bearer token for userID.
func IssueToken(secret []byte, userID string, ttl time.Duration) (string, error) {
	body, err := json.Marshal(claims{UserID: userID, Expiry: time.Now().Add(ttl).Unix()})
	if err != nil {
		return "", err
	}
	payload := base64.RawURLEncoding.EncodeToString(body)
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(payload))
	return payload + "." + base64.RawURLEncoding.EncodeToString(mac.Sum(nil)), nil
}

// VerifyToken validates a token and returns its user identifier.
func VerifyToken(secret []byte, token string) (string, error) {
	parts := strings.Split(token, ".")
	if len(parts) != 2 {
		return "", errors.New("invalid token")
	}
	mac := hmac.New(sha256.New, secret)
	_, _ = mac.Write([]byte(parts[0]))
	signature, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil || !hmac.Equal(signature, mac.Sum(nil)) {
		return "", errors.New("invalid token signature")
	}
	body, err := base64.RawURLEncoding.DecodeString(parts[0])
	var value claims
	if err != nil || json.Unmarshal(body, &value) != nil || value.UserID == "" {
		return "", errors.New("invalid token claims")
	}
	if time.Now().Unix() >= value.Expiry {
		return "", errors.New("token expired")
	}
	return value.UserID, nil
}
