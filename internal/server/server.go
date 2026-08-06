// Package server implements the authenticated GophKeeper HTTP API.
package server

import (
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/example/goph-keeper/internal/domain"
	"github.com/example/goph-keeper/internal/security"
)

// Repository describes the persistent operations required by the HTTP API.
//
// Implementations must isolate items by userID and enforce optimistic locking
// in Put.
type Repository interface {
	CreateUser(ctx context.Context, username, hash string) (string, error)
	UserByName(ctx context.Context, username string) (string, string, error)
	List(ctx context.Context, userID string) ([]domain.Item, error)
	Put(ctx context.Context, userID, itemID string, request domain.PutItem) (domain.Item, error)
}

// Server is an HTTP handler for the GophKeeper API.
type Server struct {
	repository Repository
	secret     []byte
	log        *slog.Logger
}

// New constructs an API server.
func New(repository Repository, tokenSecret []byte, logger *slog.Logger) *Server {
	if logger == nil {
		logger = slog.Default()
	}
	return &Server{repository: repository, secret: append([]byte(nil), tokenSecret...), log: logger}
}

// Handler returns the complete HTTP API router.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
	})
	mux.HandleFunc("POST /v1/register", s.register)
	mux.HandleFunc("POST /v1/login", s.login)
	mux.Handle("GET /v1/items", s.authorize(http.HandlerFunc(s.list)))
	mux.Handle("PUT /v1/items/{id}", s.authorize(http.HandlerFunc(s.put)))
	return recoverMiddleware(mux, s.log)
}

func (s *Server) register(w http.ResponseWriter, r *http.Request) {
	var credentials domain.Credentials
	if !decode(w, r, &credentials) {
		return
	}
	if len(strings.TrimSpace(credentials.Username)) < 3 || len(credentials.Password) < 8 {
		writeError(w, http.StatusBadRequest, "username must have 3 characters and password 8 characters")
		return
	}
	hash, err := security.PasswordHash(credentials.Password)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not secure password")
		return
	}
	id, err := s.repository.CreateUser(r.Context(), credentials.Username, hash)
	if errors.Is(err, domain.ErrUsernameTaken) {
		writeError(w, http.StatusConflict, domain.ErrUsernameTaken.Error())
		return
	}
	if err != nil {
		s.log.Error("create user", "error", err)
		writeError(w, http.StatusInternalServerError, "could not create user")
		return
	}
	s.respondToken(w, id, http.StatusCreated)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var credentials domain.Credentials
	if !decode(w, r, &credentials) {
		return
	}
	id, hash, err := s.repository.UserByName(r.Context(), credentials.Username)
	if err != nil || !security.CheckPassword(credentials.Password, hash) {
		writeError(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	s.respondToken(w, id, http.StatusOK)
}

func (s *Server) respondToken(w http.ResponseWriter, id string, status int) {
	token, err := security.IssueToken(s.secret, id, 24*time.Hour)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not issue token")
		return
	}
	writeJSON(w, status, domain.TokenResponse{Token: token})
}

func (s *Server) authorize(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		header := strings.TrimSpace(r.Header.Get("Authorization"))
		if !strings.HasPrefix(header, "Bearer ") {
			writeError(w, http.StatusUnauthorized, "bearer token required")
			return
		}
		id, err := security.VerifyToken(s.secret, strings.TrimPrefix(header, "Bearer "))
		if err != nil {
			writeError(w, http.StatusUnauthorized, "invalid or expired token")
			return
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), userIDKey{}, id)))
	})
}

func (s *Server) list(w http.ResponseWriter, r *http.Request) {
	items, err := s.repository.List(r.Context(), userIDFromContext(r.Context()))
	if err != nil {
		s.log.Error("list items", "error", err)
		writeError(w, http.StatusInternalServerError, "could not list items")
		return
	}
	writeJSON(w, http.StatusOK, items)
}

func (s *Server) put(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" || len(id) > 128 {
		writeError(w, http.StatusBadRequest, "invalid item id")
		return
	}
	var request domain.PutItem
	if !decode(w, r, &request) {
		return
	}
	if !request.Deleted && request.Ciphertext == "" {
		writeError(w, http.StatusBadRequest, "ciphertext is required")
		return
	}
	item, err := s.repository.Put(r.Context(), userIDFromContext(r.Context()), id, request)
	if errors.Is(err, domain.ErrConflict) {
		writeJSON(w, http.StatusConflict, item)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not store item")
		return
	}
	writeJSON(w, http.StatusOK, item)
}

type userIDKey struct{}

func userIDFromContext(ctx context.Context) string {
	userID, _ := ctx.Value(userIDKey{}).(string)
	return userID
}

func decode(w http.ResponseWriter, r *http.Request, target any) bool {
	defer func() { _ = r.Body.Close() }()
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 16<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeError(w, http.StatusBadRequest, "invalid JSON")
		return false
	}
	return true
}

func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, domain.ErrorResponse{Error: message})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func recoverMiddleware(next http.Handler, logger *slog.Logger) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		defer func() {
			if recovered := recover(); recovered != nil {
				logger.Error("request panic", "error", recovered)
				writeError(w, http.StatusInternalServerError, "internal server error")
			}
		}()
		next.ServeHTTP(w, r)
	})
}
