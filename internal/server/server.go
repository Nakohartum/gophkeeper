// Package server implements the authenticated GophKeeper HTTP API.
package server

import (
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/example/goph-keeper/internal/domain"
	"github.com/example/goph-keeper/internal/security"
	"github.com/example/goph-keeper/internal/store"
)

// Repository describes the persistent operations required by the HTTP API.
//
// Implementations must isolate items by userID and enforce optimistic locking
// in Put.
type Repository interface {
	CreateUser(username, hash string) (string, error)
	UserByName(username string) (string, string, error)
	List(userID string) []domain.Item
	Put(userID, itemID string, request domain.PutItem) (domain.Item, error)
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
	id, err := s.repository.CreateUser(credentials.Username, hash)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	s.respondToken(w, id, http.StatusCreated)
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	var credentials domain.Credentials
	if !decode(w, r, &credentials) {
		return
	}
	id, hash, err := s.repository.UserByName(credentials.Username)
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
		r.Header.Set("X-GophKeeper-User", id)
		next.ServeHTTP(w, r)
	})
}

func (s *Server) list(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, http.StatusOK, s.repository.List(r.Header.Get("X-GophKeeper-User")))
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
	item, err := s.repository.Put(r.Header.Get("X-GophKeeper-User"), id, request)
	if errors.Is(err, store.ErrConflict) {
		writeJSON(w, http.StatusConflict, item)
		return
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "could not store item")
		return
	}
	writeJSON(w, http.StatusOK, item)
}

func decode(w http.ResponseWriter, r *http.Request, target any) bool {
	defer r.Body.Close()
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
