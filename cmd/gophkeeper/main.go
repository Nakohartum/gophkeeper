// Command gophkeeper is the cross-platform GophKeeper CLI client.
package main

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/example/goph-keeper/internal/client"
	"github.com/example/goph-keeper/internal/domain"
	"github.com/example/goph-keeper/internal/security"
)

var (
	version   = "dev"
	buildDate = "unknown"
)

type config struct {
	Server   string        `json:"server"`
	Username string        `json:"username"`
	Token    string        `json:"token"`
	Items    []domain.Item `json:"items,omitempty"`
}

// remoteAPI is the subset of the remote service used by the CLI.
//
// It is declared at the consumer boundary so command logic can be tested
// independently from HTTP.
type remoteAPI interface {
	Register(context.Context, domain.Credentials) (string, error)
	Login(context.Context, domain.Credentials) (string, error)
	List(context.Context, string) ([]domain.Item, error)
	Put(context.Context, string, string, domain.PutItem) (domain.Item, error)
}

var _ remoteAPI = (*client.API)(nil)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return nil
	}
	if args[0] == "version" || args[0] == "--version" {
		fmt.Printf("gophkeeper %s (%s)\n", version, buildDate)
		return nil
	}
	configPath := os.Getenv("GOPHKEEPER_CONFIG")
	if configPath == "" {
		dir, err := os.UserConfigDir()
		if err != nil {
			return err
		}
		configPath = filepath.Join(dir, "gophkeeper", "client.json")
	}
	cfg, err := loadConfig(configPath)
	if err != nil {
		return err
	}
	serverURL := os.Getenv("GOPHKEEPER_SERVER")
	if serverURL == "" {
		serverURL = cfg.Server
	}
	if serverURL == "" {
		serverURL = "http://127.0.0.1:8080"
	}
	api, err := client.New(serverURL, nil)
	if err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	switch args[0] {
	case "register", "login":
		return authCommand(ctx, api, &cfg, configPath, serverURL, args[0], args[1:])
	case "add":
		return addCommand(ctx, api, &cfg, configPath, args[1:])
	case "list", "sync":
		return listCommand(ctx, api, &cfg, configPath, args[0] == "list")
	case "get":
		if len(args) != 2 {
			return errors.New("usage: gophkeeper get ID")
		}
		return getCommand(ctx, api, &cfg, configPath, args[1])
	case "delete":
		if len(args) != 2 {
			return errors.New("usage: gophkeeper delete ID")
		}
		return deleteCommand(ctx, api, &cfg, configPath, args[1])
	default:
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func authCommand(ctx context.Context, api remoteAPI, cfg *config, path, serverURL, command string, args []string) error {
	flags := flag.NewFlagSet(command, flag.ContinueOnError)
	username := flags.String("username", "", "account username")
	password := flags.String("password", "", "account password (or GOPHKEEPER_PASSWORD)")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *password == "" {
		*password = os.Getenv("GOPHKEEPER_PASSWORD")
	}
	if *username == "" || *password == "" {
		return errors.New("username and password are required")
	}
	credentials := domain.Credentials{Username: *username, Password: *password}
	var token string
	var err error
	if command == "register" {
		token, err = api.Register(ctx, credentials)
	} else {
		token, err = api.Login(ctx, credentials)
	}
	if err != nil {
		return err
	}
	cfg.Server, cfg.Username, cfg.Token = serverURL, *username, token
	if err = saveConfig(path, *cfg); err == nil {
		fmt.Println("authenticated as", *username)
	}
	return err
}

func addCommand(ctx context.Context, api remoteAPI, cfg *config, path string, args []string) error {
	flags := flag.NewFlagSet("add", flag.ContinueOnError)
	kind := flags.String("type", "text", "credential, text, binary, or card")
	name := flags.String("name", "", "display name")
	data := flags.String("data", "", "secret text or JSON object")
	file := flags.String("file", "", "binary file to store")
	meta := flags.String("meta", "", "arbitrary metadata")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *name == "" {
		return errors.New("name is required")
	}
	values := map[string]string{"value": *data}
	if strings.HasPrefix(strings.TrimSpace(*data), "{") {
		if err := json.Unmarshal([]byte(*data), &values); err != nil {
			return fmt.Errorf("invalid data JSON: %w", err)
		}
	}
	if *file != "" {
		raw, err := os.ReadFile(*file)
		if err != nil {
			return err
		}
		*kind = string(domain.TypeBinary)
		values = map[string]string{"filename": filepath.Base(*file), "base64": base64.StdEncoding.EncodeToString(raw)}
	}
	itemType := domain.ItemType(*kind)
	if itemType != domain.TypeCredential && itemType != domain.TypeText && itemType != domain.TypeBinary && itemType != domain.TypeCard {
		return errors.New("unsupported item type")
	}
	key, err := vaultKey(cfg)
	if err != nil {
		return err
	}
	sealed, err := client.SealSecret(key, domain.Secret{Type: itemType, Name: *name, Data: values, Meta: *meta})
	if err != nil {
		return err
	}
	id, err := client.NewID()
	if err != nil {
		return err
	}
	item, err := api.Put(ctx, cfg.Token, id, domain.PutItem{Ciphertext: sealed})
	if err != nil {
		return err
	}
	cfg.Items = append(cfg.Items, item)
	if err = saveConfig(path, *cfg); err == nil {
		fmt.Println(item.ID)
	}
	return err
}

func listCommand(ctx context.Context, api remoteAPI, cfg *config, path string, display bool) error {
	items, err := api.List(ctx, cfg.Token)
	if err != nil {
		return err
	}
	cfg.Items = items
	if err = saveConfig(path, *cfg); err != nil {
		return err
	}
	if !display {
		fmt.Printf("synchronized %d records\n", len(items))
		return nil
	}
	key, err := vaultKey(cfg)
	if err != nil {
		return err
	}
	for _, item := range items {
		if item.Deleted {
			continue
		}
		secret, openErr := client.OpenSecret(key, item.Ciphertext)
		if openErr != nil {
			return fmt.Errorf("decrypt %s: check password: %w", item.ID, openErr)
		}
		fmt.Printf("%s\t%s\t%s\tv%d\n", item.ID, secret.Type, secret.Name, item.Version)
	}
	return nil
}

func getCommand(ctx context.Context, api remoteAPI, cfg *config, path, id string) error {
	if err := listCommand(ctx, api, cfg, path, false); err != nil {
		return err
	}
	key, err := vaultKey(cfg)
	if err != nil {
		return err
	}
	for _, item := range cfg.Items {
		if item.ID == id && !item.Deleted {
			secret, err := client.OpenSecret(key, item.Ciphertext)
			if err != nil {
				return err
			}
			output, _ := json.MarshalIndent(secret, "", "  ")
			fmt.Println(string(output))
			return nil
		}
	}
	return errors.New("item not found")
}

func deleteCommand(ctx context.Context, api remoteAPI, cfg *config, path, id string) error {
	if err := listCommand(ctx, api, cfg, path, false); err != nil {
		return err
	}
	for _, item := range cfg.Items {
		if item.ID == id && !item.Deleted {
			_, err := api.Put(ctx, cfg.Token, id, domain.PutItem{Version: item.Version, Deleted: true})
			if err == nil {
				fmt.Println("deleted", id)
			}
			return err
		}
	}
	return errors.New("item not found")
}

func vaultKey(cfg *config) ([]byte, error) {
	if cfg.Token == "" || cfg.Username == "" {
		return nil, errors.New("authenticate first")
	}
	password := os.Getenv("GOPHKEEPER_PASSWORD")
	if password == "" {
		return nil, errors.New("set GOPHKEEPER_PASSWORD to encrypt or decrypt secrets")
	}
	return security.VaultKey(cfg.Username, password), nil
}

func loadConfig(path string) (config, error) {
	data, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return config{}, nil
	}
	if err != nil {
		return config{}, err
	}
	var cfg config
	err = json.Unmarshal(data, &cfg)
	return cfg, err
}

func saveConfig(path string, cfg config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(cfg, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0o600)
}

func usage() {
	fmt.Println("usage: gophkeeper <register|login|add|list|get|delete|sync|version> [options]")
}
