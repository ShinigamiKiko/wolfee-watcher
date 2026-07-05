# scanner-agent (с интеграцией ФСТЭК БДУ)

Этот архив — **полная версия** scanner-agent с уже применёнными изменениями
для поддержки маппинга CVE → BDU-ID (ФСТЭК).

## Что нового по сравнению с оригиналом

### Новое

- `internal/bdu/bdu.go` — клиент БДУ ФСТЭК. Скачивает
  `https://bdu.fstec.ru/files/documents/vulxml.zip`, парсит XML, строит
  in-memory map `CVE-ID → BDU-ID`, обновляется раз в сутки.
- `internal/bdu/bdu_test.go` — 4 unit-теста, проходят.

### Изменено

- `internal/types.go` — в `type CVE struct` добавлены два поля:
  `BduID string` и `BduSeverity string`.
- `internal/epss/enricher.go` — импорт пакета `bdu`, поле `bdu *bdu.Enricher`
  в struct, метод `WithBDU()`, блок применения BDU-lookup в `applyEnrichment`.
- `cmd/main.go` — запуск BDU-enricher-а и подключение его к основному
  enricher-у через `.WithBDU()`.

## Сборка

```bash
cd scanner-agent
go mod tidy
go build ./...
go test ./internal/bdu/   # должно быть PASS
```

## Новые переменные окружения

| Переменная          | По умолчанию                                        | Описание |
|---------------------|-----------------------------------------------------|---|
| `BDU_ARCHIVE_URL`   | `https://bdu.fstec.ru/files/documents/vulxml.zip`   | URL архива БДУ (для air-gapped контуров укажи зеркало) |
| `BDU_DISABLE`       | (не установлено)                                    | Если установлено в любое значение — BDU-enricher не запускается |

## Деплой

```bash
docker build -t localhost/wolfee-watcher/scanner-agent:fstec .
kubectl set image deploy/scanner-agent -n wolfee-watcher \
  scanner-agent=localhost/wolfee-watcher/scanner-agent:fstec
kubectl rollout status deploy/scanner-agent -n wolfee-watcher
```

## Проверка

Через 30–60 секунд после рестарта в логах должно появиться:

```
[main] BDU (ФСТЭК) enricher attached
[bdu] refreshed: NNNN CVE->BDU mappings loaded from https://bdu.fstec.ru/...
```

Если сетевого доступа к `bdu.fstec.ru` нет:

```
[bdu] initial refresh failed: ... (continuing with empty map)
```

— это не фатально, модуль будет пытаться обновиться в фоне раз в сутки,
scanner-agent продолжает работать как раньше.

После следующего сканирования образа в структуре `CVE` у части записей
появятся заполненные поля `bduId` и `bduSeverity`. Покрытие не 100% —
БДУ содержит подмножество всех CVE, это нормально.

## Offline-деплой (air-gapped)

1. Скачай `vulxml.zip` вручную с `https://bdu.fstec.ru/files/documents/vulxml.zip`
2. Положи на внутренний HTTP-сервер, доступный из кластера
3. Задай переменную окружения:

```yaml
env:
  - name: BDU_ARCHIVE_URL
    value: "http://internal-mirror.corp.local/bdu/vulxml.zip"
```

## Отключение

Если по какой-то причине нужно временно отключить BDU без передеплоя кода:

```bash
kubectl set env deploy/scanner-agent -n wolfee-watcher BDU_DISABLE=1
```
