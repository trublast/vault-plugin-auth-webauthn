# Vault Auth Plugin: WebAuthn

Плагин аутентификации HashiCorp Vault через протокол WebAuthn (пассключи, FIDO2). Позволяет регистрировать пользователей и входить с помощью аппаратных ключей или встроенных биометрических authenticator'ов.

## Возможности

- **Конфигурация через API**: настройка `rp_id`, `rp_display_name`, `rp_origins` через endpoint `config`
- **Регистрация пользователей**: `register/begin` и `register/finish` для привязки WebAuthn-ключей к пользователю
- **Вход**: `login/begin` и `login/finish` для аутентификации и получения Vault-токена
- **Discoverable (passkey) flow**: вход без ввода имени — браузер показывает выбор пассключа, пользователь определяется по `userHandle` в ответе
- Хранение пользователей и учётных данных в storage Vault (не в памяти)

## Сборка

```bash
make build
# или
go build -o plugins/webauthn ./cmd/vault-auth-plugin-webauthn
```

## Установка в Vault

1. Скопируйте бинарник в каталог плагинов Vault и зарегистрируйте плагин:

```bash
vault plugin register -command=webauthn -sha256=<sha256 бинарника> auth webauthn
```

или

```
vault server -dev -dev-plugin-dir=./plugins
```

2. Включите метод аутентификации:

```bash
vault auth enable -path=webauthn webauthn
```

3. Настройте Relying Party (обязательно перед регистрацией и входом):

```bash
vault write auth/webauthn/config \
  rp_id="localhost" \
  rp_display_name="My Vault" \
  rp_origins="http://localhost:8200,https://vault.example.com"
```

- `rp_id` — идентификатор Relying Party (обычно хост без порта; для localhost допустимо `localhost`).
- `rp_origins` — список разрешённых origin'ов (URL без пути), с которых вызывается WebAuthn (должны совпадать с тем, откуда открывается UI Vault).

## Веб-приложение (демо)

Сервер на Go раздаёт страницу с кнопками «Регистрация» и «Вход» и проксирует запросы в Vault (без CORS). Запуск:

```bash
make build-web
./webauthn-web
```

Откройте в браузере: **http://localhost:8080**

Перед использованием добавьте origin веб-приложения в конфиг:

```bash
vault write auth/webauthn/config \
  rp_id="localhost" \
  rp_display_name="My Vault" \
  rp_origins="http://localhost:8080,http://localhost:8200"
```

## Регистрация пользователя

1. Начать регистрацию (получить options для браузера):

```bash
vault write auth/webauthn/register/begin username=alice
```

В ответе — объект `PublicKeyCredentialCreationOptions` (в т.ч. `challenge`, `rp`, `user`). Клиент (браузер или скрипт) должен вызвать `navigator.credentials.create()` с этими options и отправить результат на шаг 2.

2. Завершить регистрацию (отправить credential с клиента):

```bash
vault write auth/webauthn/register/finish \
  username=alice \
  credential="$(cat credential.json)"
```

Формат `credential` — JSON объекта `PublicKeyCredential` (поля `id`, `rawId`, `type`, `response` с `clientDataJSON`, `attestationObject` и т.д.), как возвращает Web Authn API браузера.

## Вход (логин)

### С указанием имени (username-based)

1. Начать вход:

```bash
vault write auth/webauthn/login/begin username=alice
```

В ответе — `PublicKeyCredentialRequestOptions`. Клиент вызывает `navigator.credentials.get()` и передаёт результат на шаг 2.

2. Завершить вход (получить Vault token):

```bash
vault write auth/webauthn/login/finish \
  username=alice \
  credential="$(cat assertion.json)"
```

При успехе в ответе будет выдан Vault auth token (и метаданные), как при любом другом auth method.

### Discoverable (passkey) — без ввода имени

Пользователь выбирает пассключ в браузере; личность определяется по `userHandle` в ответе authenticator'а. Подходит для пользователей, зарегистрированных **после** добавления discoverable flow (для них в storage записан индекс `user_id` → username).

1. Начать вход (без `username`):

```bash
vault write auth/webauthn/login/begin
```

В ответе — options без `allowCredentials`; браузер покажет выбор пассключа (например, «Войти с помощью passkey»).

2. Завершить вход (без `username`):

```bash
vault write auth/webauthn/login/finish credential="$(cat assertion.json)"
```

Пользователь определяется по `response.userHandle` из assertion; в ответе выдан Vault token с соответствующим `username` в метаданных.

## Управление пользователями

Доступ к этим endpoint'ам требует валидного Vault-токена (в т.ч. выданного через WebAuthn).

- **Список пользователей**: `vault list auth/webauthn/user/`
- **Просмотр пользователя**: `vault read auth/webauthn/user/<name>` — возвращает `username`, `display_name`, число учётных записей (`credentials`), `user_id_b64` (без секретов)
- **Удаление пользователя**: `vault delete auth/webauthn/user/<name>` — удаляет пользователя и все его WebAuthn-ключи, а также запись в индексе для discoverable-входа

## API (кратко)

| Путь | Метод | Описание |
|------|--------|----------|
| `config` | GET | Прочитать конфигурацию |
| `config` | POST/PUT | Записать конфигурацию (`rp_id`, `rp_display_name`, `rp_origins`) |
| `user/` | LIST | Список зарегистрированных пользователей |
| `user/:name` | GET | Просмотр пользователя (метаданные, число credentials) |
| `user/:name` | DELETE | Удалить пользователя и все его credentials |
| `register/begin` | POST | Начать регистрацию (body: `username`) |
| `register/finish` | POST | Завершить регистрацию (body: `username`, `credential`) |
| `login/begin` | POST | Начать вход. С `username` — options для этого пользователя; без `username` — discoverable (выбор пассключа в браузере) |
| `login/finish` | POST | Завершить вход (body: `credential`, опционально `username`). Без `username` — пользователь определяется по userHandle (discoverable) |

Эндпоинты `register/*` и `login/*` помечены как unauthenticated, чтобы клиент мог вызывать их до входа в Vault.

## Зависимости

- [go-webauthn/webauthn](https://github.com/go-webauthn/webauthn) — в репозитории используется локальная копия из `examples/webauthn` (см. `go.mod`).
