# CryptoBlin

[English](README.md) · [Русский](README_ru.md)

Self-hosted сервис обмена заметками и файлами с моделью zero-knowledge.

Сервер хранит только зашифрованный текст и никогда не видит ни ключа
шифрования, ни пароля, ни открытых данных. Вся криптография выполняется в
браузере отправителя (или в CLI `blin`); задача сервера — отдать тот же
зашифрованный блок тому, кто может доказать обладание ключом.

Название — сокращение от **Crypto Blob Insert**, одновременно совпадающее
с русским словом **блин**: тонкий, лёгкий, съедаемый за один присест.

Проект вдохновлён [PrivateBin](https://github.com/PrivateBin/PrivateBin);
CryptoBlin — его идейное современное продолжение, ориентированное на
простоту, производительность и заметно более удобную работу с большими
файловыми вложениями.

---

## Возможности

- Полная zero-knowledge модель: на сервере лежат только шифротекст и
  тампер-устойчивый proof-of-key challenge.
- AEAD XChaCha20-Poly1305 с ключом, производным через Argon2id.
- Опциональный пароль (отдельный вход в KDF).
- Burn-after-read: запись атомарно удаляется при первом успешном открытии.
- Удаление автором по одноразовому capability-токену.
- Экспоненциальная зависимость TTL от размера: маленькие записи живут
  максимальное время, крупные — быстро истекают.
- Decoy-ответы: открытие несуществующего id возвращает ту же форму, что и
  реальный, поэтому существование id не зондируемо.
- C++ сервер с одним бинарём (Crow + SQLite + libsodium на стороне клиента);
  SPA-бандл встроен внутрь бинаря на этапе сборки.
- Кросс-платформенный CLI (`blin`) для Linux и Windows, пригоден к статической
  сборке.

---

## Архитектура

```
                        ┌────────────────────────┐
   ┌─────────┐  https   │     cryptoblin (C++)   │
   │ browser │◀────────▶│  Crow router           │
   └────┬────┘          │  ┌──────────────────┐  │     ┌──────────────┐
        │ libsodium     │  │ SQLite metadata  │  │     │ blob files   │
        ▼ (WASM, in JS) │  └──────────────────┘  │     │ (one per id) │
   plaintext / file     │  ┌──────────────────┐  │     └──────────────┘
        │               │  │ in-memory:       │  │             ▲
        ▼ AEAD          │  │  rate-limit, PoW │  │             │
   ciphertext ──────────▶  │  replay set,     │──┼─────────────┘
                        │  │  /open sessions  │  │
                        │  └──────────────────┘  │
                        └────────────────────────┘

   key  =  Argon2id(seed + ":" + password,
                    salt = blake2b("cryptoblin/v1/" + seed))
   key  живёт только в URL-фрагменте (#…), на сервер не уходит.
```

### Бинарный формат на проводе

Запрос `POST /api/pastes` представляет собой единый бинарный поток:

```
[ 33 байта  challenge plaintext ] [32 random | 1 байт burn-флаг]
[ 24 байта  challenge nonce     ]
[ 49 байт   challenge ciphertext] (AEAD над plaintext, 16-байтный тег)
[  N байт   envelope            ] [1 ver | 24 nonce | ct + 16 mac]
```

Envelope оборачивает пользовательский payload:

```
[ 1 байт format ] (0 = text, 1 = markdown, 2 = code)
[ u16 langLen   ][ utf-8 lang   ]
[ u32 textLen   ][ utf-8 text   ]
[ u16 nameLen   ][ utf-8 имя файла   ]
[ u16 mimeLen   ][ utf-8 mime файла  ]
[ u32 fileLen   ][ сырые байты файла ]
```

33-й байт challenge plaintext — burn-флаг — фиксируется на этапе создания и
аутентифицирован AEAD от и до: сервер однократно читает его в открытом виде
при создании ряда, а получатель, дешифровав challenge, видит ровно тот бит,
который установил отправитель.

### URL-фрагменты

Маршрутизация полностью клиентская. Путь всегда `/`; всё остальное — во
фрагменте, который браузеры на сервер не передают:

```
/#<id>:<seed>          →  открыть, без пароля
/#<id>:<seed>:p        →  открыть, запросить пароль
/#del:<id>:<token>     →  удаление автором (выдаётся однократно при создании)
```

`id` — 8 алфавитно-цифровых символов; `seed` — 8 символов base62; `token` —
16 случайных байтов в base64.

### Формула срока жизни

TTL — экспоненциальный спад между min и max, привязанный к концам диапазона:

```
ratio = (size − 1 KiB) / (max_paste_bytes − 1 KiB)
ttl   = min_ttl + (max_ttl − min_ttl) · (e^(−5·ratio) − e^−5) / (1 − e^−5)
```

Кривая держит «полку» на высоте максимума почти весь диапазон, а резкий
спуск к `min_ttl` сосредоточен возле верхней границы. При значениях по
умолчанию (30 дней / 1 час, при cap = 100 МиБ):

| размер     | TTL          |
|------------|--------------|
| ≤ 1 КиБ    | 30 дней      |
| 10 МиБ     | ~ 18 дней    |
| 50 МиБ     | ~ 2.3 дня    |
| 90 МиБ     | ~ 4.2 часа   |
| 100 МиБ    | 1 час        |

---

## API

Все ответы — JSON, если не оговорено отдельно. Ошибки имеют форму
`{ "error_code": "<код>", "message": "<опц.>" }` со статусом 4xx/5xx.

| Метод   | Путь                        | Назначение                                           |
|---------|-----------------------------|------------------------------------------------------|
| `GET`   | `/api/config`               | имя/заголовок приложения, версия, лимиты             |
| `GET`   | `/api/captcha`              | выпустить свежий подписанный PoW-токен               |
| `POST`  | `/api/pastes`               | создать запись (raw octet-stream в теле)             |
| `POST`  | `/api/pastes/{id}/open`     | получить challenge `nonce` + `ciphertext`            |
| `POST`  | `/api/pastes/{id}/blob`     | предъявить расшифрованный plaintext, забрать blob    |
| `DELETE`| `/api/pastes/{id}`          | удаление автором (заголовок `X-Delete-Token`)        |

### Поток создания

1. Клиент запрашивает `/api/captcha` → `{ token, difficulty }`.
2. Клиент перебирает nonce так, чтобы
   `leading_zero_bits(SHA-256(token + ":" + nonce)) ≥ difficulty`.
3. Клиент собирает бинарный формат, шлёт `POST /api/pastes` с заголовками
   `X-Pow-Token` / `X-Pow-Nonce`. Сервер повторно проверяет и потребляет
   токен (одноразовый replay-set), считывает burn-бит из 32-го байта
   plaintext, пишет ряд в БД и блоб на диск.
4. Сервер возвращает `{ id, expires_at, size, ttl_seconds, burn, delete_token }`.

### Поток открытия

1. `POST /api/pastes/{id}/open` →
   `{ token, challenge: { nonce, ciphertext } }`. Несуществующие id получают
   синтетический decoy с равномерно случайными байтами той же формы; никакая
   мета на этом шаге не утекает.
2. Клиент дешифрует challenge своим ключом, извлекает proof-plaintext (и
   burn-флаг — нужен, чтобы показать предупреждение «запись будет уничтожена»
   до запроса blob).
3. `POST /api/pastes/{id}/blob` с телом `{ token, plaintext: <b64> }`. Сервер
   constant-time-сравнивает с сохранённым plaintext. На совпадении блоб
   стримится в ответе; при `burn=true` ряд атомарно удаляется до отправки
   тела. Счётчик просмотров и burned-флаг возвращаются в response-заголовках.

### Поток удаления

`DELETE /api/pastes/{id}` с заголовком `X-Delete-Token: <b64>`. Сервер хранит
SHA-256(token); constant-time сравнение и `DELETE` выполняются за один SQL-вызов.
Отсутствие токена, неверный токен и отсутствие id одинаково сворачиваются в
`403 bad_token` без отличимого по времени поведения.

---

## Модель угроз

CryptoBlin защищает конкретные данные от конкретных атакующих. Это не магия;
описанные ниже ограничения существенны.

### Что закрывается

- **Любопытный, но честный администратор сервера.** На сервере лежат
  шифротекст, случайная соль, непрозрачный AEAD-challenge и SHA-256 от
  delete-токена. Чтение диска не даёт plaintext. Никакого ключа в депонировании.
- **Кража БД / резервной копии.** То же самое — украденная база раскрывает
  размеры записей и временные метки, но не их содержимое.
- **TLS-терминатор / reverse-proxy.** То же — ключ шифрования никогда не
  попадает в HTTP-трафик. Он живёт исключительно в URL-фрагменте, который
  браузеры не передают.
- **Пассивный сетевой наблюдатель.** Шифр — XChaCha20-Poly1305; пароли
  обрабатываются Argon2id с `OPSLIMIT_INTERACTIVE` / `MEMLIMIT_INTERACTIVE`.
  Без HTTPS наблюдатель не может прочесть содержимое; с HTTPS — также не
  видит id и размеры.
- **Подмена шифротекста сервером.** AEAD аутентифицирует envelope. Burn-флаг
  отдельно фиксируется внутри AEAD-plaintext, поэтому сервер не может тихо
  переключить `burn=false → burn=true` (или наоборот) для записей, которые
  он расшифровать не способен.
- **Зондирование существования.** `/api/pastes/{id}/open` возвращает
  одинаковую JSON-форму для реального и отсутствующего id. `/blob` сводит
  все режимы отказа к `403 bad_key`. Decoy-challenge — равномерно случайные.
- **Гонка burn-after-read.** Burn реализован как атомарный
  `DELETE … WHERE id = ?`; ряд достаётся только одному `/blob`-запросу,
  остальные получают `bad_key`.
- **Captcha-replay и злоупотребление.** PoW-токен подписан HMAC, одноразовый
  и с TTL. Выпуск captcha ограничен по IP, чтобы вредоносный клиент не мог
  переполнить replay-set.
- **Случайный burn.** CLI и web-клиент дешифруют burn-флаг **до** вызова
  `/blob`; если он установлен, пользователю показывается подтверждение, что
  запись будет уничтожена при продолжении.

### Что НЕ закрывается

- **Скомпрометированная конечная точка.** Кейлоггер, вредоносное расширение
  браузера или подменённый бинарь `blin` на одной из сторон тривиально ломают
  модель. Сверяйте релизы (подписанные tarball'ы и относительно
  воспроизводимые сборки через CI на GitHub).
- **Активный MITM без HTTPS.** Атакующий, способный переписать отдаваемый
  HTML, подменит бандл и сольёт URL-фрагмент. В продакшене обязательно
  HTTPS.
- **Перебор слабых паролей.** Argon2id настроен на интерактивную стоимость;
  четырёхсимвольный пароль всё ещё перебираем. Используйте полноценные
  пароли или полагайтесь только на ключ из URL.
- **Утечка/повтор полного URL.** Любой, кому виден URL целиком (включая
  фрагмент), читает запись до истечения TTL или burn. Относитесь к URL как
  к секрету.
- **Анонимность / метаданные.** Сервер по умолчанию логирует IP для
  rate-limit и выпуска PoW. CryptoBlin — про секретность содержимого, а не
  анонимность. Если важна анонимность, используйте Tor / прокси.
- **Отказ в обслуживании.** PoW + per-IP rate-limit + size-cap повышают
  стоимость массового создания, но решительный атакующий с пулом IP всё
  равно может забивать чтениями или заполнять cap. Для прикладных
  layer-7-лимитов ставьте перед сервисом обычный HTTP-фронтенд (nginx /
  caddy).

---

## Сборка

### Сервер (Debian 12+ / Ubuntu LTS)

```sh
sudo apt install build-essential cmake pkg-config \
                 libsqlite3-dev libsodium-dev libmbedtls-dev libasio-dev \
                 nodejs npm

cd web && npm ci && npm run build && bash embed.sh && cd ..
cmake -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build -j
./build/src/cryptoblin --config /etc/cryptoblin.ini
```

`cmake --install build` устанавливает `cryptoblin` и `blin` в префикс.

### Только CLI (`blin`)

```sh
cmake -B build -DBUILD_SERVER=OFF -DBUILD_CLI=ON
cmake --build build -j
```

### CLI под Windows

CI собирает статичный `blin.exe` через vcpkg. Локальная сборка:

```pwsh
vcpkg install libsodium:x64-windows-static-md mbedtls:x64-windows-static-md
cmake -B build -DBUILD_SERVER=OFF -DBUILD_CLI=ON `
  -DCMAKE_TOOLCHAIN_FILE="$env:VCPKG_INSTALLATION_ROOT/scripts/buildsystems/vcpkg.cmake" `
  -DVCPKG_TARGET_TRIPLET=x64-windows-static-md
cmake --build build --config Release -j
```

---

## Конфигурация (`config.ini`)

```ini
[server]
log_level    = info
bind_address = 0.0.0.0
bind_port    = 8080
app_name     = CryptoBlin
title        =                 # опц. переопределение для хедера и <title>

[storage]
db_path  = /var/lib/cryptoblin/cryptoblin.sqlite
blob_dir = /var/lib/cryptoblin/blobs

[retention]
max_paste_bytes = 104857600    # 100 МиБ
min_ttl_seconds = 3600
max_ttl_seconds = 2592000

[limits]
rate_limit_per_ip_seconds = 3
total_pastes_cap          = 0  # 0 = без ограничения

[captcha]
difficulty_bits = 18
ttl_seconds     = 300
```

---

## CLI

```sh
echo "secret" | blin send                        # текст со stdin
blin send -b README.md                            # burn-after-read, только файл
echo "see attached" | blin send report.pdf       # текст + вложение
blin get https://paste.dotcpp.ru/#abcd1234:wxyz5678
blin delete https://paste.dotcpp.ru/#del:abcd1234:AAA…
```

URL сервера читается из `$HOME/.config/askhatovich/cryptoblin/config.conf`
(формат: `SERVER=https://example.com`); по умолчанию —
`https://paste.dotcpp.ru`.

`blin --help` описывает все флаги и контракт stdout/stderr (полезные данные
на stdout, машинно-парсимые `key: value` на stderr).

---

## Разработка

```sh
# юнит-тесты сервера
ctest --test-dir build --output-on-failure

# end-to-end тесты против реально запущенного бинаря
cd web && node --test tests/
```

Релизы выпускаются через GitHub Actions при пуше тегов `v*`: Linux-tarball'ы
для Debian 12 и Debian 13 (сервер + CLI) и Windows-zip с `blin.exe`.
SHA-256-суммы лежат рядом с каждым артефактом.

---

## Лицензия

GPL-3.0-or-later. См. [LICENSE](LICENSE).
