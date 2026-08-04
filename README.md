# GophKeeper

GophKeeper — клиент-серверное хранилище секретов на Go. Сервер отвечает за
регистрацию, аутентификацию, авторизацию, постоянное хранение и синхронизацию.
Содержимое секретов шифруется на клиенте с помощью AES-256-GCM, поэтому сервер
хранит только непрозрачный шифротекст.

Поддерживаются пары логин/пароль, текст, бинарные файлы, банковские карты и
произвольная текстовая метаинформация. HTTP API описан в
[`api/openapi.yaml`](api/openapi.yaml).

## Запуск

Требуется Go 1.25 или новее.

```text
go test ./...
go run ./cmd/server -addr :8080 -data data/server.json
```

Для постоянства пользовательских сессий серверу нужен секрет не короче
32 случайных символов:

```text
GOPHKEEPER_TOKEN_SECRET=change-this-to-a-long-random-value
```

В production следует передать `-tls-cert` и `-tls-key` либо разместить сервер
за TLS reverse proxy. Пароли никогда не сохраняются клиентом, но токен и
зашифрованный локальный кэш записываются с правами только для владельца.

## CLI

Адрес сервера задаётся переменной `GOPHKEEPER_SERVER` (по умолчанию
`http://127.0.0.1:8080`). Пароль можно передать флагом только при входе и
регистрации; для шифрования и расшифрования используется
`GOPHKEEPER_PASSWORD`.

```text
gophkeeper register -username alice -password "long password"
gophkeeper login    -username alice -password "long password"

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

В PowerShell переменная задаётся как
`$env:GOPHKEEPER_PASSWORD = "long password"`.

## Синхронизация и конфликты

Каждый объект имеет монотонную версию. Запись принимается только с версией,
которую клиент получил последней; устаревшее изменение получает HTTP `409`.
Удаления представлены tombstone-записями и поэтому распространяются на другие
клиенты. `sync` загружает актуальный набор зашифрованных записей в локальный
кэш, а `list` и `get` синхронизируются перед выводом.

## Сборка

Версия и дата внедряются через `ldflags`:

```text
go build -ldflags "-X main.version=v1.0.0 -X main.buildDate=2026-07-30" ./cmd/gophkeeper
```

Скрипт `scripts/build.ps1` выпускает CLI для Windows, Linux и macOS в каталог
`build/`.

## Архитектура и безопасность

- `cmd/server` — HTTP-сервис;
- `cmd/gophkeeper` — переносимый CLI;
- `internal/server` — REST API и bearer-авторизация;
- `internal/store` — атомарно сохраняемое JSON-хранилище;
- `internal/security` — PBKDF2-HMAC-SHA256, HMAC-токены и AES-GCM;
- `internal/client` — API-клиент и шифрование секретов.

Границы компонентов выражены небольшими интерфейсами со стороны потребителя:
`server.Repository` отделяет HTTP API от конкретного хранилища,
`client.HTTPDoer` — API-клиент от HTTP-транспорта, а CLI зависит только от
необходимого ему набора операций удалённого API. Благодаря этому файловое
хранилище, транспорт и серверный клиент можно заменять тестовыми либо
production-реализациями без изменения бизнес-логики.

Пароль на сервере представлен индивидуально посоленным PBKDF2-verifier с
120 000 итераций. Ключ хранилища детерминированно выводится на клиенте из имени
и пароля; на сервер не отправляются ключ, открытые данные или метаинформация.
Токены подписаны HMAC-SHA256 и действуют 24 часа.
