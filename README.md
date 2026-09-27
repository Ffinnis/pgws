# PGWS

Начальная реализация [RFC-0001 revision 0.3](docs/RFC-0001.md). Go 1.25, PostgreSQL и HTTP/JSON API. Проект находится в отдельной папке и содержит копию RFC и контрактов.

Работает физический сценарий PostgreSQL 18: регистрация источника, потоковый baseline, создание ZFS-клона через API, `latest`, подписанный barrier и `at_least`, TLS-подключение с отдельными credentials, pause/resume, reset, продление TTL и удаление. Исходные логины отключаются. Пароли для повторного ответа хранятся в management database только в зашифрованном виде.

В Linux VM проверены настоящие PostgreSQL 18.6, OpenZFS и Docker. Сквозной тест запускает API, worker, host, ingress guard и CLI отдельными процессами. Независимый guard закрывает существующие SQL-соединения при истечении serving lease, workspace или credentials. Отдельный watchdog контролирует WAL и останавливает просроченные runtime.

Проект получает общий ZFS-лимит для baseline, снимков и клонов. Watchdog также закрывает доступ при нехватке места в пуле. Счётчики и точный смысл лимитов описаны в [STORAGE-ACCOUNTING.md](docs/STORAGE-ACCOUNTING.md).

Это рабочая физическая реализация для отдельного локального стенда. Поддержаны одобренные Unix-источники и TCP-источники через TLS-посредник с закреплёнными IP, один application database и консервативный список PostgreSQL-функций. Настройка TCP описана в [SOURCE-TLS.md](docs/SOURCE-TLS.md). Sanitized ingestion, обучение классификатора и все production acceptance gates RFC ещё не завершены. Точное состояние и ограничения находятся в [IMPLEMENTATION.md](docs/IMPLEMENTATION.md).

## Постоянный локальный стенд

```sh
python3 scripts/dev.py up
python3 scripts/dev.py status
python3 scripts/dev.py cli baselines
```

Обновить работающий стенд с сохранением данных: `python3 scripts/dev.py upgrade`.
Сквозная проверка обновления: `python3 scripts/dev_upgrade_check.py`.
Создать новый пример после истечения TTL: `python3 scripts/dev.py workspace`.

Стенд создаёт собственные source/management PostgreSQL 18, ZFS pool и пример workspace на один час. API доступен на `http://127.0.0.1:18870`. API и worker работают под разными непривилегированными пользователями Linux. Команда `python3 scripts/dev.py down` удаляет ресурсы этого стенда. Настройка подключения, TLS и ограничения описаны в [LOCAL-SERVICE.md](docs/LOCAL-SERVICE.md).

Для программного доступа доступны [Python и TypeScript SDK](sdk/README.md).

Замер создания нескольких баз через API и проверки изоляции SQL:
`python3 scripts/benchmark.py --baseline BASELINE_UUID --workspaces 2 --rounds 2`.
Методика и пределы измерений описаны в [BENCHMARK.md](docs/BENCHMARK.md).

Для приватного sanitized-кандидата добавлен `pgws-logical`: обнаружение схемы, согласованная начальная загрузка и поток изменений с преобразованием данных. Проверены повтор после потерянного ACK и остановка при неизвестном поле. Публичная выдача sanitized-workspace пока закрыта; профиль и команды описаны в [LOGICAL-ADAPTER.md](docs/LOGICAL-ADAPTER.md).

Для будущего локального классификатора добавлены `pgws-features` и `pgws-classify`. Первый экспортирует признаки, второй проверяет подпись файла весов и вычисляет оценки классов. Обученных весов пока нет; все результаты требуют ручной проверки. Формат и ограничения описаны в [CLASSIFIER-RUNTIME.md](docs/CLASSIFIER-RUNTIME.md).

## Проверка

```sh
make build
make test
make sdk-test
make integration
make physical-lab
make zfs-lab
make host-lab
```

`make integration` требует `initdb`, `pg_ctl` и `postgres` одной установки в PATH. Скрипт создаёт приватный временный кластер без TCP, запускает HTTP/SQL-тесты с race detector, останавливает кластер и удаляет его. Локально этот прогон проверен на PostgreSQL 14.20 и 18.6 (Homebrew).

`make physical-lab` требует Docker. Он запускает management-тесты и физическое восстановление в отдельных контейнерах PostgreSQL 18 с закреплённым digest, отключённой сетью и временным хранилищем. Существующие базы и контейнеры не используются. Подробности и команды `pgws-physical` — в [PHYSICAL-LAB.md](docs/PHYSICAL-LAB.md).

Статические проверки исходных контрактов:

```sh
python3 -m pip install -r contracts/requirements.txt
python3 contracts/validate_contracts.py
python3 contracts/classifier/validate.py
```

`make zfs-lab` и `make host-lab` используют выделенную Lima VM `pgws-lab` с Linux, OpenZFS и Docker. Каждый прогон создаёт отдельный файловый ZFS pool и временные базы, затем удаляет свои ресурсы. `host-lab` проверяет также отдельные процессы сервиса. Тесты не используют пользовательские базы или физические диски.

## Запуск API

Нужна отдельная пустая management database. Миграции создают схему `pgws_control` и роль `pgws_runtime`; migration user должен иметь права создания роли. Обновлённые SQL-файлы нельзя подменять после применения: runner проверяет SHA-256 миграций.

```sh
export PGWS_DATABASE_URL='postgres://USER:PASSWORD@127.0.0.1:5432/pgws?sslmode=disable'
./bin/pgwsd migrate
mkdir -p .local
chmod 700 .local
umask 077
./bin/pgwsd bootstrap > .local/bootstrap.json
```

Bootstrap выполняется один раз. Он создаёт tenant, project, authority epoch и административный токен на 24 часа. Файл содержит секрет; он исключён из Git. Повторный bootstrap не меняет существующую или восстановленную authority.

```sh
export PGWS_AUTHORITY_EPOCH=$(python3 -c 'import json; print(json.load(open(".local/bootstrap.json"))["authority_epoch"])')
export PGWS_PROJECT_ID=$(python3 -c 'import json; print(json.load(open(".local/bootstrap.json"))["project_id"])')
export PGWS_TOKEN=$(python3 -c 'import json; print(json.load(open(".local/bootstrap.json"))["token"])')
./bin/pgwsd serve
```

API слушает `127.0.0.1:8080`. `/healthz` проверяет процесс, `/readyz` проверяет management authority и сообщает, настроен ли physical backend. Это проверка конфигурации API, а не готовности конкретного workspace. Для внешнего доступа нужен TLS reverse proxy. Проект пока рассчитан на локальную разработку; production login-роли и OIDC ещё не реализованы. Команды выпуска, просмотра, ротации и отзыва API-токенов описаны в [TOKEN-ADMIN.md](docs/TOKEN-ADMIN.md).

В другом терминале с теми же переменными:

```sh
./bin/pgws baselines
./bin/pgwsd worker
```

Для API и worker используйте отдельные login-роли без `SUPERUSER`, `BYPASSRLS` и владения таблицами, с членством в `pgws_runtime` и `pgws_worker` соответственно. Миграции и bootstrap выполняет только migration owner. HTTP-обработчики понижают роль до `pgws_runtime` внутри каждой транзакции. Локальный стенд создаёт раздельные роли автоматически.

## CLI

Все ответы выводятся как JSON. Ошибка API или завершившаяся неудачей операция дают ненулевой exit code. CLI не следует HTTP redirects с bearer token. Для изменяющих запросов нужен явный `--key`; используйте прежний ключ при сетевом повторе.

```sh
./bin/pgws create --file request.json --key create-task-42
./bin/pgws get --id WORKSPACE_UUID
./bin/pgws action --id WORKSPACE_UUID --file action.json --key pause-task-42
./bin/pgws operation --id OPERATION_UUID
./bin/pgws wait --id OPERATION_UUID --timeout 2m
./bin/pgws delete --id WORKSPACE_UUID --generation 1 --key delete-task-42
```

`source`, `barrier` и `credentials` принимают JSON через `--file`. Форматы находятся в [OpenAPI](contracts/openapi.yaml). Завершение ожидания не удаляет workspace. Пример запроса не следует отправлять с придуманным snapshot: ingestion должна сначала создать и подтвердить его.

## Код

- `cmd/pgwsd`: миграции, bootstrap, HTTP-сервер и worker.
- `cmd/pgws`: CLI.
- `cmd/pgws-host`, `cmd/pgws-guard`, `cmd/pgws-watchdog`: привилегированный host, TLS ingress с отдельным процессом и независимый контроль ресурсов.
- `cmd/pgws-physical`: локальные административные команды inspect/barrier/seed/recover/stop.
- `cmd/pgws-logical`: приватные административные команды discover/seed/run/barrier/status; `internal/privacy` и `internal/logical` — компилятор политик, экспортированный снимок и транзакционный CDC.
- `internal/physical`: discovery, подтверждённый backup, отключённое восстановление и доказательства replay/promotion.
- `internal/storage/zfs`: создание baseline/snapshot/clone, holds, проверка ownership/GUID и нерекурсивное удаление клона.
- `internal/control`: транзакционное принятие запросов, права, lifecycle, очередь и fencing попыток.
- `internal/migrations`: исходная SQL-схема RFC и миграция прав/API.
- `internal/lease`: подписи Ed25519, проверка serving lease, монотонные deadlines и файловый журнал fencing с fsync и блокировкой процесса. Её используют worker и отдельный ingress guard.
- `contracts`: неизменённые контракты RFC, включая спецификацию классификатора.

Дальнейшая реализация всех WP-01–WP-12, ограничения текущего кода и следующие acceptance tests перечислены в [IMPLEMENTATION.md](docs/IMPLEMENTATION.md).

Administrator source recovery is available through `pgws source-get` and
`pgws source-action`. See [source generations](docs/SOURCE-RESEED.md) for reseed
admission, preserved workspace lineage and reconciliation restrictions.

Private discovery and classifier workflows are documented in
[bounded PostgreSQL discovery](docs/BOUNDED-DISCOVERY.md),
[offline training](ml/column-classifier/README.md), and
[local model scoring](docs/CLASSIFIER-RUNTIME.md).
The private logical adapter also supports [committed marker barriers](docs/LOGICAL-BARRIERS.md).
These tools do not enable the public sanitized connector.

Приватный загрузчик теперь работает внутри контейнера базовой копии. Отдельный watchdog проверяет WAL источника, останавливает контейнер и удаляет только подтверждённый слот. Проверены замороженная начальная загрузка, CDC и восстановление снимков ZFS. Подробности и оставшиеся ограничения: [LOGICAL-SUPERVISION.md](docs/LOGICAL-SUPERVISION.md).

Добавлены административные команды `pgwsd policy-create/show/approve/sign/revoke`. Они сохраняют проверяемую привязку политики и подписывают решение, но пока не открывают публичные sanitized-базы. Порядок работы: [PRIVACY-ADMIN.md](docs/PRIVACY-ADMIN.md).

История измерений доступна через `pgws usage` и метод `usage` обоих SDK.
Host сохраняет пакет до подтверждения управляющей базы; повторная доставка
не создаёт дубликаты. Семантика и ограничения: [USAGE.md](docs/USAGE.md).

Восстановление управляющей базы выполняется через `pgwsd recovery-init/begin/finish`
и `pgws-host recover`. Старые разрешения отзываются, процессы останавливаются,
данные остаются закрытыми на диске. Проверены настоящий backup/restore PostgreSQL
18, аварийные остановки процедуры и создание новой рабочей БД после повторного
одобрения доступа. Порядок действий: [MANAGEMENT-RECOVERY.md](docs/MANAGEMENT-RECOVERY.md).

Приватный логический загрузчик поддерживает автоматическое продление одобрения:
`pgwsd policy-renew` доставляет подписи отдельному `pgws-logical-watchdog relay`.
Отзыв политики прекращает продление и останавливает CDC в пределах срока
последнего разрешения. Настройка: [PRIVACY-ADMIN.md](docs/PRIVACY-ADMIN.md).
