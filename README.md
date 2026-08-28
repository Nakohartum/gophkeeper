# GophKeeper

GophKeeper — клиент-серверное хранилище секретов на Go. Содержимое и
метаинформация шифруются клиентом с помощью AES-256-GCM, поэтому сервер хранит
в PostgreSQL только непрозрачный шифротекст.

Поддерживаются пары логин/пароль, текст, бинарные файлы, банковские карты и
произвольная текстовая метаинформация. HTTP API описан в
[`api/openapi.yaml`](api/openapi.yaml).

## Запуск

Требуются Go 1.26 и PostgreSQL. Для локального запуска БД:

```text
docker compose -f deployments/docker-compose.yml up -d
```

Затем задайте конфигурацию и запустите сервер:

```text
GOPHKEEPER_DATABASE_DSN=postgres://gophkeeper:gophkeeper@localhost:5432/gophkeeper?sslmode=disable
GOPHKEEPER_TOKEN_SECRET=change-this-to-a-long-random-value
go run ./cmd/server -addr :8080
```

В PowerShell переменные задаются через `$env:ИМЯ = "значение"`. Все ожидающие
`up`-миграции встроены в сервер и транзакционно применяются при запуске. В production следует передать
`-tls-cert` и `-tls-key` либо разместить сервер за TLS reverse proxy.

## Миграции базы данных

Миграции находятся в каталоге `migrations/` и выполняются по возрастанию
числовой версии:

- `000001_create_users` создаёт таблицу пользователей;
- `000002_create_items` создаёт зашифрованные записи и индекс синхронизации.

Применённые версии сохраняются в `schema_migrations` вместе с SHA-256 checksum.
Изменение уже применённого SQL обнаруживается при следующем старте. Advisory
lock не позволяет нескольким экземплярам сервера одновременно изменять схему.
Для программного отката предназначена функция `migrations.Down(ctx, db, steps)`;
соответствующие `.down.sql`-файлы удаляют объекты в обратном порядке.

## CLI

Адрес сервера задаётся переменной `GOPHKEEPER_SERVER` и по умолчанию равен
`http://127.0.0.1:8080`. При интерактивном запуске пароль считывается из
терминала без эха. Для автоматизированных сценариев его можно передать через
`GOPHKEEPER_PASSWORD`; флага командной строки для пароля намеренно нет.

```text
gophkeeper register -username alice
gophkeeper login -username alice

GOPHKEEPER_PASSWORD="long password" gophkeeper add \
  -type credential -name example.com \
  -data '{"login":"alice","password":"secret"}' -meta "work"

GOPHKEEPER_PASSWORD="long password" gophkeeper add \
  -type card -name primary \
  -data '{"number":"4111111111111111","expiry":"12/30","cvv":"123"}'

GOPHKEEPER_PASSWORD="long password" gophkeeper add \
  -name archive -file ./archive.bin -meta "backup"

GOPHKEEPER_PASSWORD="long password" gophkeeper list
GOPHKEEPER_PASSWORD="long password" gophkeeper get ITEM_ID
gophkeeper delete ITEM_ID
gophkeeper sync
gophkeeper version
```

Токен и зашифрованный локальный кэш сохраняются в пользовательском каталоге
конфигурации. Пароль не сохраняется.

## Синхронизация и конфликты

Каждый объект имеет монотонную версию. Сервер принимает изменение только с
версией, которую клиент получил последней; устаревшее изменение получает HTTP
`409 Conflict`. Удаления представлены tombstone-записями и синхронизируются с
другими клиентами. `sync` загружает актуальный зашифрованный набор в локальный
кэш, а `list` и `get` синхронизируются перед выводом.

## Проверка и сборка

```text
go test -race -cover ./...
go vet ./...
golangci-lint run
```

Версия и дата внедряются через `ldflags`:

```text
go build -ldflags "-X main.version=v1.0.0 -X main.buildDate=2026-08-06" ./cmd/gophkeeper
```

Скрипт `scripts/build.ps1` выпускает CLI для Windows, Linux и macOS в каталог
`build/`.

## Архитектура и безопасность

- `cmd/server` — HTTP-сервис, lifecycle и graceful shutdown;
- `cmd/gophkeeper` — переносимый CLI со скрытым вводом пароля;
- `internal/server` — REST API и bearer-авторизация;
- `internal/store` — PostgreSQL и тестовая файловая реализация репозитория;
- `internal/security` — PBKDF2-HMAC-SHA256, HMAC-токены и AES-GCM;
- `internal/client` — API-клиент и шифрование секретов.

`server.Repository` отделяет HTTP API от реализации хранилища, а
`client.HTTPDoer` — API-клиент от HTTP-транспорта. Пароль на сервере хранится
как индивидуально посоленный PBKDF2-verifier со 120 000 итераций. Ключ
хранилища выводится на клиенте из имени и пароля; ключ, открытые данные и
метаинформация на сервер не отправляются. Токены подписаны HMAC-SHA256 и
действуют 24 часа.
