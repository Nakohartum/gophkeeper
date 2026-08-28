package security

import (
	"strings"
	"testing"
	"time"
)

func TestPasswordHash(t *testing.T) {
	hash, err := PasswordHash("correct horse battery staple")
	if err != nil {
		t.Fatal(err)
	}
	if !CheckPassword("correct horse battery staple", hash) {
		t.Fatal("correct password rejected")
	}
	if CheckPassword("wrong password", hash) {
		t.Fatal("wrong password accepted")
	}
	for _, malformed := range []string{"", "x", "pbkdf2-sha256$x$x$x", "pbkdf2-sha256$1$YQ$YQ"} {
		if CheckPassword("password", malformed) {
			t.Fatalf("malformed hash accepted: %q", malformed)
		}
	}
}

func TestEncryptDecrypt(t *testing.T) {
	key := VaultKey("Alice", "password")
	ciphertext, err := Encrypt(key, []byte("secret"))
	if err != nil {
		t.Fatal(err)
	}
	plaintext, err := Decrypt(key, ciphertext)
	if err != nil || string(plaintext) != "secret" {
		t.Fatalf("round trip = %q, %v", plaintext, err)
	}
	if _, err = Decrypt(VaultKey("Alice", "other"), ciphertext); err == nil {
		t.Fatal("wrong key accepted")
	}
	if _, err = Decrypt(key, "not base64!"); err == nil {
		t.Fatal("malformed ciphertext accepted")
	}
	if short := strings.TrimRight(ciphertext[:4], "="); short != "" {
		if _, err = Decrypt(key, short); err == nil {
			t.Fatal("short ciphertext accepted")
		}
	}
}

func TestToken(t *testing.T) {
	secret := []byte("01234567890123456789012345678901")
	token, err := IssueToken(secret, "user-1", time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	id, err := VerifyToken(secret, token)
	if err != nil || id != "user-1" {
		t.Fatalf("verify = %q, %v", id, err)
	}
	if _, err = VerifyToken([]byte("another secret"), token); err == nil {
		t.Fatal("invalid signature accepted")
	}
	expired, _ := IssueToken(secret, "user-1", -time.Second)
	if _, err = VerifyToken(secret, expired); err == nil {
		t.Fatal("expired token accepted")
	}
	for _, malformed := range []string{"", "a.b.c", "a.?", "e30.invalid"} {
		if _, err = VerifyToken(secret, malformed); err == nil {
			t.Fatalf("invalid token accepted: %q", malformed)
		}
	}
}
