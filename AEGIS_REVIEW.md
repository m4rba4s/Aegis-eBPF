# AEGIS (eBPF/XDP Firewall) — обзор и ревью проекта

Документ основан на текущем состоянии кода в каталоге `eBPF_Firewall/` в репозитории `LazyCat`.
Цель — дать понятный обзор архитектуры и перечислить проблемные места/риски, чтобы их можно было быстро исправить.

## 1) Что такое AEGIS (кратко)

**AEGIS** — eBPF/XDP firewall + мониторинг в TUI:
- eBPF-программа (`aegis-ebpf`) вешается на интерфейс через XDP и фильтрует входящий трафик максимально рано.
- userspace CLI/TUI (`aegis-cli`) загружает eBPF, читает события из perf buffer, управляет BPF maps (ручной бан/разбан, toggles модулей), умеет подтягивать threat-feeds.

Сценарий из README: «киберпанк TUI», “space-to-ban”, эвристики (Xmas/Null/SYN+FIN), rate limit SYN, port-scan detection, CIDR-блоклист из threat-feeds.

## 2) Структура (workspace)

Rust workspace: `eBPF_Firewall/Cargo.toml`

- `eBPF_Firewall/aegis-ebpf/` — eBPF/XDP программа (Rust + Aya eBPF)
- `eBPF_Firewall/aegis-cli/` — userspace CLI/TUI (Aya userspace, tokio, ratatui)
- `eBPF_Firewall/aegis-common/` — общие структуры/константы (no_std)
- `eBPF_Firewall/xtask/` — вспомогательная сборка eBPF (`cargo run -p xtask -- build-ebpf`)
- `eBPF_Firewall/deploy/` — systemd unit + deploy-скрипт и “идеальная” YAML-конфигурация (но сейчас она не подключена к коду напрямую)

## 3) Сборка / запуск (как сейчас работает)

### 3.1 Пререквизиты (минимум)

- Linux Kernel `>= 5.8` + BTF (`/sys/kernel/btf/vmlinux`)
- Rust toolchain (stable) + **nightly** для сборки eBPF target через `xtask`
- `bpf-linker` (требуется `aegis-ebpf/.cargo/config.toml`)
- libelf/zlib dev-пакеты (см. `eBPF_Firewall/README.md`)
- Запуск требует root или нужных capabilities (`CAP_BPF`, `CAP_NET_ADMIN`, `CAP_SYS_RESOURCE` и т.п.)

### 3.2 Сборка

Из `eBPF_Firewall/`:

```bash
# eBPF объект
cargo run -p xtask -- build-ebpf --profile release

# userspace CLI
cargo build --release -p aegis-cli
```

eBPF бинарник собирается в `eBPF_Firewall/target/bpfel-unknown-none/release/aegis` (ELF-объект).
CLI собирается в `eBPF_Firewall/target/release/aegis-cli`.

### 3.3 Установка (скрипт)

`eBPF_Firewall/install.sh`:
- собирает eBPF + CLI
- копирует eBPF в `/usr/local/share/aegis/aegis.o`
- копирует CLI в `/usr/local/bin/aegis-cli`

⚠️ Важно: скрипт требует `sudo`, при этом сборка “под root” часто ломается из‑за окружения rust/cargo (и в скрипте заявлен `--install-only`, но он не реализован).

### 3.4 Запуск

CLI ожидает eBPF объект **по жёстко заданному пути**: `/usr/local/share/aegis/aegis.o` (`aegis-cli/src/main.rs`).

Примеры:

```bash
sudo /usr/local/bin/aegis-cli -i eth0 tui
sudo /usr/local/bin/aegis-cli -i wg0-mullvad tui
sudo /usr/local/bin/aegis-cli -i eth0 load     # REPL режим
sudo /usr/local/bin/aegis-cli -i eth0 daemon   # headless
```

### 3.5 Тесты

Тесты есть только в `aegis-cli/src/feeds/parser.rs` (парсер feed-строк).

## 4) Архитектура и поток данных

### 4.1 Поток “пакет → решение → событие → TUI”

1) XDP получает пакет на интерфейсе.
2) `aegis-ebpf/src/main.rs` парсит IPv4 + (TCP/UDP порты).
3) Применяются:
   - whitelist (private/CGNAT/localhost)
   - conntrack fast-path (частично)
   - scan detection (Xmas/Null/SYN+FIN)
   - port scan detection
   - SYN rate-limit (token bucket)
   - CIDR блоклист (LPM trie; сейчас фактически /32)
   - ручной блоклист (точный матч + wildcard)
4) При PASS/DROP (и в verbose режиме даже при PASS) пишется `PacketLog` в `EVENTS` perf buffer.
5) `aegis-cli` читает perf events, печатает/рисует в TUI, при некоторых threat_type делает auto-ban (OODA) через `BLOCKLIST`.

### 4.2 eBPF maps (фактически интерфейсы между kernel/userspace)

Определены в `eBPF_Firewall/aegis-ebpf/src/main.rs`:

- `BLOCKLIST: HashMap<FlowKey, u32>` — ручные блоки (и auto-ban); key = `(src_ip, dst_port, proto)` + wildcard `(dst_port=0, proto=0)` для “забанить IP целиком”
- `CIDR_BLOCKLIST: LpmTrie<..., CidrBlockEntry>` — блоклист из threat feeds (задумано под префиксы)
- `EVENTS: PerfEventArray<PacketLog>` — события в userspace
- `CONFIG: HashMap<u32, u32>` — runtime toggles (0=L2/L3 mode; 1..5 модули; 6 verbose)
- `RATE_LIMIT: HashMap<u32, RateLimitState>` — токен‑бакет по source IP
- `PORT_SCAN: HashMap<u32, PortScanState>` — состояние портскана по source IP
- `CONN_TRACK: HashMap<ConnTrackKey, ConnTrackState>` — stateful fast-path (но без cleanup)
- `STATS: PerCpuArray<Stats>` — счётчики (сейчас **не обновляются**)

## 5) CLI/TUI (что умеет и как устроено)

### 5.1 Команды

`aegis-cli/src/main.rs`:

- `tui` — интерактивный дашборд (ratatui) + “space to ban”
- `load` — загрузка XDP + REPL (ручные команды block/unblock/save/restore/list)
- `daemon` — headless режим (без REPL)
- `feeds update|list|stats|load` — заготовка для threat feeds

### 5.2 TUI hotkeys

`aegis-cli/src/tui/mod.rs`:

- `↑/↓` — навигация
- `Space` — бан/разбан IP (через `BLOCKLIST` wildcard)
- `q` — выход
- `1..5` — включить/выключить модули (через `CONFIG` map)
- `0` — toggle всех модулей 1..5
- `6` — verbose

⚠️ Сейчас есть рассинхрон между тем, что показывает TUI, и тем, что реально делает eBPF (см. раздел 7).

### 5.3 Geo lookup

В TUI есть geo‑обогащение через `ip-api.com` по HTTP (`aegis-cli/src/tui/mod.rs`).
Это:
- сетевой запрос (может быть заблокирован/ограничен)
- утечка наблюдаемых IP во внешнюю систему
- отсутствие TLS (HTTP)

## 6) Конфигурация (фактическая vs. заявленная)

### 6.1 `aegis.yaml` (фактически используется)

Код читает **только** `aegis.yaml` из текущей директории (`aegis-cli/src/main.rs`), структура задаётся `aegis-cli/src/config.rs`:

- `rules: []` — набор ручных правил для `BLOCKLIST`
- `remote_log: "host:port"` — UDP syslog‑подобная отправка JSON событий

Пример:

```yaml
remote_log: "127.0.0.1:514"
rules:
  - ip: 1.2.3.4
    port: 0
    proto: tcp
    action: drop
```

⚠️ `action` сейчас не влияет — вставляется значение `2` как “DROP”.

### 6.2 `deploy/config.yaml` (сейчас НЕ подключён)

`eBPF_Firewall/deploy/config.yaml` содержит богатую конфигурацию (thresholds, whitelist, feeds, logging…), но:
- `aegis-cli` это не читает
- значения не прокидываются в `CONFIG` и не управляют константами в eBPF

Итог: сейчас это скорее “план/спека”, чем рабочая конфигурация.

## 7) Основные проблемы/риски (по приоритету)

### P0 (критично, стоит исправить первым)

1) **Подозрительный systemd unit**  
`eBPF_Firewall/aegis.service` запускает `/usr/local/bin/kworker-u4 ...` — это выглядит как ошибка/артефакт/маскировка.  
Для продакшна нужен единый корректный unit (скорее `deploy/aegis@.service`).

2) **Toggles модулей работают не так, как показывает TUI**  
В eBPF:
- rate-limit не проверяет `CFG_RATE_LIMIT` (toggle “2” может не влиять)
- `CFG_VERBOSE` по умолчанию фактически может оказаться **включён** (из‑за default=enabled в `is_module_enabled`)  
В TUI verbose по умолчанию показывается выключенным.

3) **Conntrack без очистки + неполная модель для inbound**  
`CONN_TRACK` имеет лимит 65536 и не очищается (timeouts объявлены, но не применяются).  
Inbound соединения к сервису на хосте не становятся “ESTABLISHED”, потому что XDP видит только ingress.

4) **Threat-feeds / CIDR работают как /32 и могут быстро забить map**  
Сейчас loader вставляет в `CIDR_BLOCKLIST` только `/32` и не сохраняет реальные префиксы (а CIDR могут быть большими).  
Плюс счётчик “loaded” инкрементится даже при ошибке вставки (map full).

5) **Жёстко зашит путь до eBPF объекта**  
`/usr/local/share/aegis/aegis.o` — снижает DX и ломает “запуск из репозитория”.

6) **Daemon mode не ориентирован на systemd stop**  
Ожидание только `ctrl_c()` (SIGINT). systemd остановка обычно SIGTERM → вероятен некорректный shutdown.

### P1 (важно)

- **Дублирование структур** (`PacketLog`, `LpmKeyIpv4`, `FlowKey`, константы) между `aegis-ebpf` и `aegis-common` → риск дрейфа ABI.
- **IPv6/VLAN** не поддержаны, но частично “намечены” константами/полями (REASON_IPV6_POLICY, ipv6_* в Stats). VLAN трафик сейчас пройдет мимо (ether_type != IPv4).
- **Port scan bitmap** использует `dst_port & 0xFF` (коллизии портов, обходы, ложные срабатывания).
- **Geo по HTTP + внешняя зависимость** (privacy/интегритет), желательно сделать отключаемым и/или offline.
- **`install.sh` собирает под root** и объявляет `--install-only`, которого нет.
- **`restore` в REPL не очищает старые правила** (можно накопить мусор в `BLOCKLIST`).

### P2 (улучшения)

- Реально использовать `STATS` и показывать метрики в TUI.
- Добавить “expiry/TTL” для auto-ban и conntrack (или LRU map).
- Поднять конфиг‑параметры (thresholds/whitelist/feeds) в userspace и прокидывать в `CONFIG`/отдельные maps.
- Добавить `--config` и `--ebpf-path` в CLI, и явную поддержку `--iface-mode l2|l3`.
- Добавить минимальный CI (fmt/clippy/test) и smoke‑check “сборка ebpf + cli”.

## 8) Репозиторные замечания (не про логику, но про гигиену)

- Внутри `eBPF_Firewall/` присутствуют `eBPF_Firewall/.git/` и `eBPF_Firewall/target/` (в т.ч. бинарники).  
  Для общего репозитория это почти всегда лишнее: увеличивает размер, путает историю, приносит артефакты сборки.

## 9) Чек‑лист “что проверить после исправлений”

- `tui` toggles реально включают/выключают соответствующие блоки в eBPF (особенно rate-limit/verbose/conntrack).
- `daemon` корректно завершается по SIGTERM, отцепляет XDP и не оставляет интерфейс “в подвешенном” состоянии.
- Threat feeds грузятся и действительно блокируют CIDR (а не только /32).
- Нет деградации сети на VLAN/IPv6 (либо это явно задокументировано как ограничение).
- Нет бесконтрольного роста maps (`CONN_TRACK`, `PORT_SCAN`, `RATE_LIMIT`, `BLOCKLIST`).

