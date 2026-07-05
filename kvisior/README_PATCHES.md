# kvisior UI (с поддержкой Stop Scan)

Все патчи применены.

## Изменения

1. `src/data/scanner.js` — новая функция `stopScan()`,
   POST на `/scanner/scan/stop`.
2. `src/context/ScannerContext.jsx` — экспорт `stopScan` через context,
   отрисовывает строку `⏹ Stop requested…` в progress log.
3. `src/pages/vuln/VulnMgmt.jsx` — кнопка `⟳ Stop Scan` (красная)
   появляется когда `scanning=true` вместо пассивной `Scanning…`.
   Добавлена кнопка `Show log / Hide log` для прогресс-панели.
4. `src/styles/components.css` + `components.scss` — добавлен
   класс `.btn-danger` (красная градиентная кнопка).

## Сборка

```bash
cd kvisior
podman build --no-cache -t localhost/wolfee-watcher/kvisior8:latest .
podman save localhost/wolfee-watcher/kvisior8:latest | ctr -n k8s.io images import -

kubectl rollout restart -n wolfee-watcher deploy/kvisior-ui
```

## Проверка

В UI на странице Vulnerability Management:

1. Нажми `🔍 Scan All Images` → запускается скан.
2. Появляется красная кнопка `⟳ Stop Scan`.
3. Нажми её → запросы прервутся, через секунду:
   - кнопка вернётся к `🔍 Scan All Images`,
   - в progress log появится `⏹ Stop requested…` и финальный
     `✓ Scan stopped by user`.

В логах scanner-agent параллельно:
```
[scan] stop requested — cancelling pool, dropping queue (had 13 pending)
[scan][w0] cancelled: ...
[scan][w1] cancelled: ...
[scan] worker pool drained (cancelled)
```
