// Command server runs the GophKeeper HTTP service.
package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/example/goph-keeper/internal/server"
	"github.com/example/goph-keeper/internal/store"
)

var (
	version   = "dev"
	buildDate = "unknown"
)

var _ server.Repository = (*store.FileStore)(nil)

func main() {
	address := flag.String("addr", ":8080", "HTTP listen address")
	data := flag.String("data", "data/server.json", "persistent store path")
	cert := flag.String("tls-cert", "", "TLS certificate path")
	key := flag.String("tls-key", "", "TLS private-key path")
	showVersion := flag.Bool("version", false, "print version and build date")
	flag.Parse()
	if *showVersion {
		fmt.Printf("gophkeeper-server %s (%s)\n", version, buildDate)
		return
	}
	repository, err := store.Open(*data)
	if err != nil {
		log.Fatal(err)
	}
	tokenSecret := []byte(os.Getenv("GOPHKEEPER_TOKEN_SECRET"))
	if len(tokenSecret) < 32 {
		tokenSecret = make([]byte, 32)
		if _, err = rand.Read(tokenSecret); err != nil {
			log.Fatal(err)
		}
		log.Print("warning: generated an ephemeral token secret; set GOPHKEEPER_TOKEN_SECRET for stable sessions")
	}
	httpServer := &http.Server{
		Addr:              *address,
		Handler:           server.New(repository, tokenSecret, nil).Handler(),
		ReadHeaderTimeout: 5 * time.Second,
		ReadTimeout:       30 * time.Second,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
	}
	log.Printf("GophKeeper server listening on %s", *address)
	if *cert != "" || *key != "" {
		err = httpServer.ListenAndServeTLS(*cert, *key)
	} else {
		err = httpServer.ListenAndServe()
	}
	if err != nil && err != http.ErrServerClosed {
		log.Fatal(err)
	}
}
