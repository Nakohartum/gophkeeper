// Command server runs the GophKeeper HTTP service.
package main

import (
	"context"
	"crypto/rand"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/example/goph-keeper/internal/server"
	"github.com/example/goph-keeper/internal/store"
)

var (
	version   = "dev"
	buildDate = "unknown"
)

var _ server.Repository = (*store.SQLStore)(nil)

func main() {
	logger := slog.New(slog.NewJSONHandler(os.Stdout, nil))
	slog.SetDefault(logger)
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	if err := run(ctx, os.Args[1:], logger); err != nil {
		logger.Error("server stopped", "error", err)
		os.Exit(1)
	}
}

func run(ctx context.Context, args []string, logger *slog.Logger) error {
	flags := flag.NewFlagSet("gophkeeper-server", flag.ContinueOnError)
	address := flags.String("addr", ":8080", "HTTP listen address")
	dsn := flags.String("database-dsn", os.Getenv("GOPHKEEPER_DATABASE_DSN"), "PostgreSQL connection string")
	cert := flags.String("tls-cert", "", "TLS certificate path")
	key := flags.String("tls-key", "", "TLS private-key path")
	showVersion := flags.Bool("version", false, "print version and build date")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *showVersion {
		fmt.Printf("gophkeeper-server %s (%s)\n", version, buildDate)
		return nil
	}
	repository, err := store.OpenPostgres(ctx, *dsn)
	if err != nil {
		return err
	}
	defer func() {
		if closeErr := repository.Close(); closeErr != nil {
			logger.Error("close PostgreSQL", "error", closeErr)
		}
	}()
	tokenSecret := []byte(os.Getenv("GOPHKEEPER_TOKEN_SECRET"))
	if len(tokenSecret) < 32 {
		tokenSecret = make([]byte, 32)
		if _, err = rand.Read(tokenSecret); err != nil {
			return fmt.Errorf("generate token secret: %w", err)
		}
		logger.Warn("generated an ephemeral token secret; set GOPHKEEPER_TOKEN_SECRET for stable sessions")
	}
	httpServer := &http.Server{
		Addr:              *address,
		Handler:           server.New(repository, tokenSecret, logger).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	serveErrors := make(chan error, 1)
	go func() {
		if *cert != "" || *key != "" {
			serveErrors <- httpServer.ListenAndServeTLS(*cert, *key)
			return
		}
		serveErrors <- httpServer.ListenAndServe()
	}()
	logger.Info("GophKeeper server started", "address", *address)
	select {
	case err = <-serveErrors:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return fmt.Errorf("serve HTTP: %w", err)
	case <-ctx.Done():
		logger.Info("shutting down GophKeeper server")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		if err = httpServer.Shutdown(shutdownCtx); err != nil {
			return fmt.Errorf("shutdown HTTP server: %w", err)
		}
		err = <-serveErrors
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			return fmt.Errorf("serve HTTP: %w", err)
		}
		return nil
	}
}
