# scanner-agent (production-ready)

Все патчи применены. Что внутри:

## Изменения относительно базовой версии

1. **Локальный ФСТЭК БДУ** — `internal/bdu/bdu.go` поддерживает чтение
   `vulxml.xml` или `vulxml.zip` с диска через env `BDU_LOCAL_PATH`.
   Никаких походов в `bdu.fstec.ru` (нет проблем с сертификатами Минцифры).
2. **Память** — после загрузки BDU вызывается `runtime.GC()` +
   `debug.FreeOSMemory()`. RES идёт с ~1.3 ГБ до ~150 МБ в idle.
3. **Параллельные сканы** — worker pool с настраиваемым числом
   воркеров через env `SCAN_WORKERS` (дефолт 2).
4. **Stop scan** — новый endpoint `POST /scan/stop`. Отменяет пул
   и убивает in-flight grype subprocess'ы через context cancel.

## Сборка

Положи `vulxml.xml` (распакованный, ~570 МБ) или `vulxml.zip` (~30 МБ)
рядом с Dockerfile:

```
scanner-agent/
├── Dockerfile
├── vulxml.xml          <-- ОБЯЗАТЕЛЬНО для BDU enricher'a
├── cmd/
├── internal/
└── ...
```

Если используешь zip — поправь Dockerfile (последняя строка с COPY):
```dockerfile
COPY vulxml.zip /opt/bdu/vulxml.zip
ENV BDU_LOCAL_PATH=/opt/bdu/vulxml.zip
```

Парсер сам определит формат по magic bytes (PK для zip).

## Команды

```bash
cd scanner-agent
podman build --no-cache -t localhost/wolfee-watcher/scanner-agent:latest .
podman save localhost/wolfee-watcher/scanner-agent:latest | ctr -n k8s.io images import -

kubectl rollout restart -n wolfee-watcher deploy/scanner-agent
sleep 15
kubectl logs -n wolfee-watcher deploy/scanner-agent --tail=50
```

## Ожидаемые логи при старте

```
[scanner-agent] starting (engine=grype, enrichment=NVD+EPSS+KEV+PoC)
[main] k8s client ready
[bdu] refreshed: 77114 CVE->BDU mappings loaded from /opt/bdu/vulxml.xml
[main] BDU (ФСТЭК) enricher attached (local: /opt/bdu/vulxml.xml)
[scanner-agent] listening on :9090
```

## Тюнинг параллелизма

В `helm/templates/scanner-agent.yaml` в env Deployment'а:

```yaml
- name: SCAN_WORKERS
  value: "2"   # дефолт, безопасно для 7-8 GB ноды
  # value: "1" — последовательно (если тачка слабая)
  # value: "4" — на 16+ GB ноде
```
