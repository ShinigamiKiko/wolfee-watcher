# tracee-bridge — fix: bounded queue вместо rate-limit на ingest

## Проблема

На `/tracee/event` стоял per-IP rate limiter (`TRACEE_INGEST_RATE_PER_MIN=6000`,
т.е. 100 rps sustained). Tracee с полным security policy (execve, ptrace, socket,
connect, mmap, mprotect, openat и т.д.) реально генерирует 1000–4000 rps на
средний кластер. В результате bridge молча резал 90%+ событий с HTTP 429,
Tracee их ретраил, и создавался retry-шторм. В логах Tracee это выглядело как:

```
{"level":"error","msg":"Error sending webhook, http status: 429"}
```

Для security-инструмента рейт-лимитить trusted upstream — антипаттерн:
теряются детекты (ptrace, memfd_create, init_module) ровно в тот момент,
когда они нужнее всего.

## Что поменялось

### `internal/server/server.go`

- **Удалено:** `ingestLimiter` (`*ratelimit.Limiter`) и `ingestSem` (semaphore).
  Их роль на `/tracee/event` полностью убрана.
- **Добавлено:** `eventQueue chan queueItem` — bounded очередь (дефолт 50000).
- **Добавлено:** пул воркеров (дефолт 8) — стартуют в `New()`, живут пока жив
  `ctx`. Каждый воркер читает из `eventQueue` и делает медленную часть:
  `podCache.Enrich` + фильтр system namespaces + `hub.Broadcast`.
- **Изменено `handleTracee`:**
  - Парсит и мапит события синхронно (быстро).
  - Неблокирующий `select` кладёт item в `eventQueue`. Если очередь
    полная — drop + `eventsDropped.Add()` + sampled warning.
  - **Всегда возвращает 200 OK.** Tracee не получает 429 → не уходит в retry.
- **Новые метрики в `/stats`:** `events_dropped`, `ingest_queue_len`,
  `ingest_queue_cap`, `ingest_queue_pct`, `ingest_workers`.

### `deploy/bridge.yaml`

- **Memory limit:** `128Mi → 512Mi` (requests: `64Mi → 256Mi`).
  50k событий в очереди × ~2KB + накладные = ~100–150MB в пике, 512Mi с запасом.
- **CPU limit:** `200m → 1000m` (requests: `50m → 100m`). 8 воркеров требуют
  больше CPU при всплесках.
- **Новые env-переменные:**
  - `TRACEE_INGEST_QUEUE_SIZE=50000`
  - `TRACEE_INGEST_WORKERS=8`

### Что НЕ тронуто

- `queryLimiter` на `/events/query` — **оставлен**. Это внешний API, там
  rate-limit концептуально правильный.
- `internal/ratelimit/ratelimit.go` — **не удалён**, используется `queryLimiter`.
- Прочие файлы (hub, mapper, payload, mtls, podcache, ratelimit, dedup,
  flows, matcher) — **не менялись**. Фикс точечный.

## Как это поведёт себя

**Нормальная нагрузка (1000–4000 rps):** очередь колеблется у нуля,
`events_dropped=0`, всё мгновенно пролетает через воркеров. 429 исчезают полностью.

**Всплеск (например, в момент старта kubelet GC / grype-db-update):**
события копятся в очереди, воркеры разгребают. При 50k буфере и
8 воркерах это абсорбирует всплески ~50 секунд при 1000 rps.

**Устойчивая перегрузка downstream (PostgreSQL тормозит, hub не успевает):**
очередь заполняется, новые события дропаются с sampled warning в логах.
**Tracee этого не видит** (всегда 200), perf-буфер Tracee не переполняется,
retry-шторма нет. В `/stats` это видно как `events_dropped > 0` и
`ingest_queue_pct ≈ 100` — сигнал к увеличению воркеров или
разбору, что тормозит downstream.

## Деплой

```bash
# Сборка образа
docker build -t localhost/wolfee-watcher/tracee-bridge:latest ./tracee-bridge

# Применение манифеста (обновит resources + env-переменные)
kubectl apply -f tracee-bridge/deploy/bridge.yaml

# Рестарт, если образ тот же тег
kubectl rollout restart deploy/tracee-bridge -n wolfee-watcher
kubectl rollout status  deploy/tracee-bridge -n wolfee-watcher
```

## Проверка после деплоя

```bash
# 1. 429 должны пропасть из логов Tracee:
kubectl logs tracee-mvr5v -n wolfee-watcher --since=5m | grep -c "429"
# Ожидаемо: 0

# 2. Stats bridge — заполнение очереди и drops:
kubectl exec -n wolfee-watcher \
  $(kubectl get pod -n wolfee-watcher -l app=tracee-bridge -o name | head -1) \
  -- wget -qO- http://localhost:8080/health    # sanity
# Для /stats нужен mTLS на :8081, дёргать из кластера (анomaly/kvisior).

# 3. Если events_dropped > 0 устойчиво — крутить:
#    - TRACEE_INGEST_WORKERS в 2–3 раза (упрётся в PostgreSQL throughput)
#    - TRACEE_INGEST_QUEUE_SIZE в 2 раза (требует больше памяти)
```

## Если нужно откатиться

Старый бинарник без bounded queue работает с переменной окружения
`TRACEE_INGEST_RATE_PER_MIN` для подъёма лимита — это был краткосрочный
workaround. Новая версия эту переменную **игнорирует** (она больше не
читается), что корректно: лимит на ingest от trusted Tracee не должен
существовать в принципе.
