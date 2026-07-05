# kvisior Helm chart — upgrade 0.2.x → 0.3.0

## Централизация схемы БД и least-privilege роли (StackRox-style)

В 0.3.0 владение схемой PostgreSQL вынесено в единый компонент:

- **Новый Job `central-migrate`** (модуль `central/`, образ
  `localhost/wolfee-watcher/central-migrate` — не забудьте пересобрать образы
  через `./1.sh`). Запускается хуком `post-install,post-upgrade`: применяет
  весь DDL, сидит дефолтного `admin`-пользователя UI и создаёт по одной
  Postgres-роли на сервис с минимальными грантами
  (`central/internal/schema/grants.go`).
- **Сервисы больше не выполняют `CREATE TABLE`** (удалены все
  `InitSchema`/`EnsureSchema`/`keepSchema`) и подключаются под собственными
  ролями (`postgres.serviceCredentials` в values.yaml). DSN владельца БД
  (`global.postgresDSN`) остаётся только у Job.
- **Новый initContainer `wait-for-schema`** у всех DB-сервисов: под не
  стартует, пока миграции не применены и его роль не создана.
- **Ретеншн таблицы `alerts` перенесён в kvisior** (Central) — раньше
  дублировался инлайном в tracee-bridge.
- **Из tracee-bridge удалены дублирующие хендлеры `/policies` и `/acks`** —
  записью политик и ack'ов владеет только kvisior (`/api/policies`,
  `/api/acks`).
- **sentry-audit и forensic-watcher полностью отключены от PostgreSQL**
  (StackRox-style: коллекторы → Central):
  - sentry-audit пушит каждое audit-событие в kvisior
    (`/internal/push/audit`), который персистит его в `audit_events` и сам
    отвечает на `/sentry/api/events` для UI; pull-опрос sentry-audit из
    kvisior-коллектора удалён. Правила алертинга агент забирает у kvisior
    (`/internal/pull/alert-rules?detType=Audit`), алерты доставляет через
    `/internal/alert-log` с флагом `persist=true` — строку в `alerts` пишет
    kvisior.
  - forensic-watcher (privileged DaemonSet) пушит файловые диффы в
    `/internal/push/forensic`, реестр watch'ей — в
    `/internal/push/forensic-watch`; историю диффов UI получает от kvisior
    (`/sensor/api/forensic/diff/{ns}/{pod}` теперь отвечает из БД, watch/tar
    по-прежнему проксируются на узел). Ретеншн `audit_events` и
    `forensic_events` (24h) выполняет kvisior.
  - Роли `ww_sentry_audit` и `ww_forensic_watcher` удаляются миграцией
    (`DROP OWNED BY` + `DROP ROLE`); их пароли из values.yaml убраны.
- **sensor тоже отключён от PostgreSQL** (роль `ww_sensor` удаляется
  миграцией):
  - собранные kubelet-логи пушатся батчами в `/internal/push/logs`; kvisior
    владеет `container_logs`, курсорами инжеста (`log_cursors`, обновляются
    на стороне kvisior при приёме батча; sensor сидит их при старте через
    `/internal/pull/log-cursors`) и 24h-ретеншном;
  - форензик-запросы логов (`sinceSeconds`, страница Forensics) sensor
    обслуживает через `/internal/pull/logs`; обычная вкладка логов как и
    раньше идёт напрямую в kubelet и БД не касается;
  - кэш снапшота для follower-реплик переехал в
    `/internal/push|pull/snapshot-cache` (таблица `snapshot_cache`);
  - alerter sensor'а (Deploy-правила) получает политики через
    `/internal/pull/alert-rules?detType=Deploy` и доставляет алерты через
    `/internal/alert-log` с `persist=true` — как sentry-audit.

- **scanner-agent отключён от PostgreSQL** (роль `ww_scanner_agent`
  удаляется миграцией). Это заодно чинит баг: helm-шаблон scanner-agent
  никогда не задавал `POSTGRES_DSN`, так что чтение Harbor-кредов из
  таблицы `integrations` в деплое не работало вовсе. Теперь агент тянет
  конфиг через `/internal/pull/integration?kind=harbor` (kvisior отдаёт
  только enabled-интеграции), Build-правила — через
  `/internal/pull/alert-rules?detType=Build`, алерты — `persist=true`.
- **anomaly-detector больше не пишет в `alerts`** — его алерты идут через
  `/internal/alert-log` с `persist=true`; грант на `alerts` у `ww_anomaly`
  снят. Свои таблицы (интеграции, baseline'ы, anomaly_events) он
  по-прежнему ведёт сам — это control-plane данные.
- **Identity (auth) перенесён из anomaly-detector в kvisior.** Раньше auth
  был расщеплён: edge-слой (куки, `RequireAuth`, `/auth/login|logout|me`)
  жил в kvisior, а хранилище (`admin_*`, проверка паролей/сессий/токенов) —
  в anomaly, и kvisior ходил туда по HTTP. Теперь весь стор живёт в kvisior
  (`internal/accounts`), валидация — in-process, без сетевого хопа; ролевая
  логика вынесена в общий `pkg/authz`. Следствия для деплоя:
  - **Гранты на `admin_*` переехали `ww_anomaly` → `ww_ui`** (kvisior
    подключается под `ww_ui`). `applyGrants` стал полностью декларативным —
    ревокает ALL по всем управляемым таблицам у роли перед выдачей её набора,
    так что `admin_*` у `ww_anomaly` снимаются автоматически. Запустите Job
    на апгрейде.
  - **anomaly остаётся за mTLS** и доверяет резолвнутой роли из заголовка
    `X-Acting-Role` (kvisior его проставляет) для своих `/api/*` — отдельный
    запрос к БД за ролью больше не нужен.
  - Фронт зовёт управление юзерами/токенами/группами по kvisior-relative
    `/api/*` вместо прокси `/anomaly/api/*`.
  - В proxy-mode (kvisior без своего Postgres) auth недоступен и отдаёт
    503 — в обычном деплое у kvisior есть пул, так что это касается только
    вырожденного режима.
- **Надёжная доставка push-путей**: `pkg/alerts.Forwarder` и
  audit-форвардер sentry-audit переведены с fire-and-forget на
  ограниченную очередь (1024) с ретраями и экспоненциальным бэкоффом
  (4 попытки); forensic-watcher сдвигает baseline снапшота только после
  подтверждённого пуша — рестарт kvisior больше не теряет события.
- **Починен `/api/events`**: kvisior регистрировал хендлер, читавший
  несуществующую таблицу `tracee_events`, и тем самым перекрывал рабочий
  прокси-путь на tracee-bridge `/events`. Хендлер удалён — запросы снова
  проксируются. Остальные `/api/*` хендлеры разнесены по store-слою
  (`internal/store/uiapi.go`).
- Удалена мёртвая заглушка `pkg/alerts.RunDelivery` и её вызовы.
- **По итогам ревью ПР-а** (вторая итерация):
  - `wait-for-schema` теперь ждёт **конкретную версию схемы**
    (`centralMigrate.schemaVersion` = `central/internal/schema.Version`,
    Job падает при расхождении) — на апгрейде новые поды не стартуют
    против старой схемы/грантов. **Не используйте `helm --wait`** —
    post-хук и гейты взаимно блокируются (см. DEPLOY.md).
  - Доставка алертов и audit-событий — через общий `pkg/alerts.PushQueue`
    с батчингом (до 64 алертов / склейка event-батчей в один POST):
    убраны head-of-line blocking при недоступном kvisior и дубликат
    кода очередей. `/internal/alert-log` принимает и батч
    `{"alerts":[...]}`, и одиночный объект (на время mixed-version
    rollout); persist-алерты пишутся синхронно одной транзакцией.
  - Индексы по `ts` для `container_logs` и `forensic_events` — hourly
    ретеншн-DELETE больше не seq-scan; свип протухших `log_cursors` (48h);
    forensic-батч вставляется одним `unnest`-стейтментом; идемпотентный
    курсор-гард для повторно доставленных лог-батчей.
  - sentry-audit: удалён мёртвый интерфейс `webhook.Storer`, in-memory
    ring урезан 5000 → 1000 (он только фолбэк, история — у kvisior).
- **Масштабирование под большие кластеры**:
  - kvisior теперь можно гонять в несколько реплик (`ui.replicaCount`):
    обработка tracee-событий — общая consumer-group (партиции делятся
    между репликами), SSE live-feed — groupless-консьюмер на каждой
    реплике (все видят всё), push-события разъезжаются по репликам через
    внутренний топик `kvisior-ui-events`, ретеншн-свипы сериализованы
    Postgres advisory-lock'ом (подметает одна реплика за тик).
  - **Сбор логов контейнеров переехал из sensor в forensic-watcher**
    (DaemonSet): каждый узел читает свой `/var/log/pods` локально и пушит
    батчи с настоящими CRI-таймстемпами — apiserver больше не в пути
    данных, нагрузка масштабируется с числом узлов. Sensor оставил себе
    только чтение истории (форензик `sinceSeconds`) и snapshot-cache.
    Новые hostPath-маунт `/var/log/pods` и настройка
    `forensicWatcher.logExcludeNamespaces` (обрезать объём на больших
    кластерах). `/internal/push/logs` принимает и старый формат
    (`ts`+`lines`) на время mixed-version rollout.
  - tracee-bridge ключует Kafka-записи `ns/pod` (раньше — только pod):
    стабильный порядок по workload'у и отсутствие коллизий имён между
    namespace'ами.

  Остальное для 500 нод — вне чарта: HA Postgres (CloudNativePG/Patroni),
  Kafka с RF=3 (`kafka.replicaCount`, `replicationFactor`, `minIsr`),
  реплики/PDB для tracee-bridge, cert-server, sentry-audit и шардирование
  anomaly-detector (stateful baseline'ы — отдельная задача).

  Прямой доступ к PostgreSQL теперь остаётся только у kvisior (Central),
  tracee-bridge (только INSERT в alerts + чтение политик) и
  anomaly-detector (его control-plane таблицы).

### Порядок апгрейда

1. `./1.sh` — собрать новые образы (включая `central-migrate`).
2. `helm upgrade wolfee-watcher ./helm -n wolfee-watcher ...` — Job
   отработает автоматически, существующие данные не трогаются (DDL
   идемпотентен и совпадает с прежним).
3. Для прод-кластера переопределите пароли в
   `postgres.serviceCredentials.*.password` — смена пароля применяется
   `ALTER ROLE` на следующем upgrade.

---

# kvisior Helm chart — upgrade 0.2.0 → 0.2.1

## Что фиксится

### Критичное: grype vulnerability DB не обновлялась

В 0.2.0 было три бага, которые вместе приводили к тому, что сканирование
образов работало с **пустым или устаревшим** кэшем уязвимостей:

1. Env `GRYPE_CACHE_DIR` вместо корректной `GRYPE_DB_CACHE_DIR`.
   grype эту переменную игнорировал и фоллбэчил на `/.cache/grype/db`,
   куда у runAsUser=65534 нет прав записи → `mkdir /.cache: permission denied`.

2. В CronJob grype-db-update команда содержала несуществующий флаг
   `--cache-dir` → `unknown flag: --cache-dir` → job падал.

3. По умолчанию `grypeCache.persistentVolume.enabled: false` (emptyDir),
   но CronJob и Deployment разворачивались **каждый со своим** emptyDir.
   Даже если бы CronJob работал, его кэш не шарился с scanner-agent.

### Исправления в 0.2.1

- `GRYPE_CACHE_DIR` → `GRYPE_DB_CACHE_DIR` + добавлены `XDG_CACHE_HOME` и
  `HOME` (страховка от разных версий grype).
- Из команды CronJob убран `--cache-dir`, путь к кэшу теперь через env.
- `persistentVolume.enabled` по умолчанию **true** (grype DB ~1 GB, при
  emptyDir каждый рестарт пода = повторная скачка).
- CronJob разворачивается **только если PVC включён** — с emptyDir он
  бессмысленен. При emptyDir scanner-agent сам обновляет БД при старте
  (`GRYPE_SKIP_DB_UPDATE=false` выставляется автоматически).

### tracee-bridge: bounded queue pipeline вместо rate-limit

В 0.2.0 был per-IP rate limiter на `/tracee/event` (100 rps) — но Tracee с
полным security policy генерирует 1000-4000 rps. bridge молча резал 90%+
событий с HTTP 429, Tracee ретраил, каскад терял security-findings.

В 0.2.1:
- Добавлены env `TRACEE_INGEST_QUEUE_SIZE` (50000) и `TRACEE_INGEST_WORKERS` (8).
- Лимиты памяти подняты 128Mi/512Mi → 256Mi/512Mi (очередь + воркеры).
- Требует **нового образа tracee-bridge** с патчем server.go (убран
  ingestLimiter, добавлен bounded queue + worker pool — см.
  `tracee-bridge-fix.zip` или архив полного компонента).

### ФСТЭК БДУ enricher

Опциональная интеграция scanner-agent с БДУ ФСТЭК (bdu.fstec.ru).
Включается по умолчанию (`scannerAgent.bdu.enabled: true`), пытается
скачать архив раз в сутки. Если сетевого доступа нет — модуль тихо
работает с пустой картой, ошибки не фатальны.

Для air-gapped контура укажите внутреннее зеркало:
```yaml
scannerAgent:
  bdu:
    enabled: true
    archiveURL: "http://internal-mirror.corp.local/bdu/vulxml.zip"
```

Или отключите совсем: `scannerAgent.bdu.enabled: false`.

Требует **нового образа scanner-agent** с BDU-модулем и патчем types.go/enricher.go
(см. архив полного компонента).

## Апгрейд

### Шаг 1. Пересобрать образы (если ещё не пересобраны)

**scanner-agent** — нужен новый образ с BDU-модулем:
```bash
cd scanner-agent  # из архива scanner-agent-full.zip
go build ./...
go test ./internal/bdu/
docker build -t localhost/wolfee-watcher/scanner-agent:latest .
```

**tracee-bridge** — нужен новый образ с bounded queue:
```bash
cd tracee-bridge  # из архива tracee-bridge-fix.zip (или полного)
go build ./...
docker build -t localhost/wolfee-watcher/tracee-bridge:latest .
```

### Шаг 2. Проверить dry-run

```bash
helm upgrade kvisior ./kvisior \
  -n wolfee-watcher \
  --dry-run --debug \
  > /tmp/kvisior-rendered.yaml

# Посмотреть разницу с текущим релизом:
helm get manifest kvisior -n wolfee-watcher > /tmp/kvisior-current.yaml
diff /tmp/kvisior-current.yaml /tmp/kvisior-rendered.yaml | less
```

### Шаг 3. Применить

**Важно:** PVC по умолчанию теперь `enabled: true`. Если в вашем кластере
нет StorageClass по умолчанию — укажите его явно:

```bash
helm upgrade kvisior ./kvisior \
  -n wolfee-watcher \
  --set scannerAgent.grypeCache.persistentVolume.storageClass=standard
```

Если не хотите PVC (например, в demo-кластере) — оставьте emptyDir:

```bash
helm upgrade kvisior ./kvisior \
  -n wolfee-watcher \
  --set scannerAgent.grypeCache.persistentVolume.enabled=false
```

В этом случае CronJob не развернётся, а scanner-agent сам будет качать
БД при старте (автоматически выставляется `GRYPE_SKIP_DB_UPDATE=false`).

### Шаг 4. Проверка

```bash
# 1. Под scanner-agent должен запуститься, БД должна подтянуться:
kubectl rollout status deploy/scanner-agent -n wolfee-watcher
kubectl logs deploy/scanner-agent -n wolfee-watcher --tail=50 | grep -iE "grype|bdu|db"

# Ожидаем одно из:
#   - если PVC: "[main] updating Grype vulnerability DB..." → "Grype DB updated"
#   - если PVC и CronJob уже отработал: "[main] k8s client ready" сразу
#   - BDU: "[bdu] refreshed: NNNN CVE->BDU mappings loaded"
#     (если bdu.fstec.ru недоступен — "initial refresh failed ..." это ok)

# 2. Если включён PVC — CronJob должен выполниться вручную успешно:
kubectl create job -n wolfee-watcher --from=cronjob/grype-db-update grype-db-update-test
kubectl logs -n wolfee-watcher job/grype-db-update-test -f
# Ожидаем: "vulnerability database updated" без permission denied

# 3. tracee-bridge — 429 должны пропасть из логов Tracee:
kubectl logs -n wolfee-watcher daemonset/tracee --tail=100 | grep -c "429"
# Ожидаем: 0

# 4. bridge stats — очередь должна быть ~пустая на нормальной нагрузке:
POD=$(kubectl get pod -n wolfee-watcher -l app.kubernetes.io/name=tracee-bridge -o name | head -1)
kubectl exec -n wolfee-watcher $POD -- wget -qO- http://localhost:8080/health
# Для stats нужен mTLS, дёргайте из кластера.
```

## Откат

```bash
helm rollback kvisior -n wolfee-watcher
```

Это вернёт предыдущий ReleaseRevision (0.2.0). Но учтите: чтобы
rollback действительно работал, надо также откатить образы
scanner-agent / tracee-bridge на старые теги, если вы их
перетёрли через `:latest`.

## Что поменялось в values.yaml

Diff против 0.2.0:

```yaml
traceeBridge:
+ ingestQueueSize: 50000
+ ingestWorkers: 8
  resources:
    requests:
-     memory: 128Mi
+     memory: 256Mi
    limits:
-     cpu: 500m
+     cpu: 1000m

scannerAgent:
  grypeCache:
    persistentVolume:
-     enabled: false
+     enabled: true
+ bdu:
+   enabled: true
+   archiveURL: ""
```

Остальные компоненты (postgres, sensor, anomaly-detector, sentry-audit,
forensic-watcher, honey-operator, audit-runner, ui, tracee, certServer,
caBootstrap) **не затрагиваются** этим релизом.
