# ByeByeVPN

**Full TSPU / DPI / VPN detectability scanner.**

Client-side Windows/Linux tool. You give it any IP or hostname, and it runs
the same test suite that TSPU / GFW / corporate DPI boxes use — then tells
you what service is there, what VPN stack is running, and how obvious it
looks to a censor.

Клиентская тулза для Windows/Linux. Скармливаешь ей IP или хостнейм, она
прогоняет полный комплекс тестов, которые использует TSPU / GFW /
корпоративный DPI — и говорит, что за сервис на IP, какой VPN-стек
работает, насколько он палится и как это чинить.

```
 ____             ____           __     ______  _   _
| __ ) _   _  ___| __ ) _   _  __\ \   / /  _ \| \ | |
|  _ \| | | |/ _ \  _ \| | | |/ _ \ \ / /| |_) |  \| |
| |_) | |_| |  __/ |_) | |_| |  __/\ V / |  __/| |\  |
|____/ \__, |\___|____/ \__, |\___| \_/  |_|   |_| \_|
       |___/            |___/
   Full TSPU/DPI/VPN detectability scanner   v2.1
```

**Jump to:** [English](#english) · [Русский](#русский)

---

## English

### What it does

Seven-phase pipeline that runs from **your** machine against a target IP/host.
You do **not** need to be connected to the target's VPN — the tool scans it
as an external observer, exactly how an ISP / TSPU / DPI middlebox sees it.

| Phase | Module                 | What it actually does                                                      |
|-------|------------------------|----------------------------------------------------------------------------|
| 1     | **DNS resolve**        | A + AAAA resolution with timing                                            |
| 2     | **GeoIP** (7 sources)  | Country, ASN, flags: hosting / VPN / proxy / Tor / abuser — in parallel    |
| 3     | **TCP port scan**      | Connect-scan 1–65535 (default) or 205 curated ports, 500 threads, banner-grab |
| 4     | **UDP probes**         | Real handshake payloads to DNS / IKE / OpenVPN / QUIC / WireGuard / Tailscale |
| 5     | **Service fingerprint**| SSH banner, HTTP probe, TLS handshake + SNI consistency, SOCKS5, CONNECT, Shadowsocks |
| 6     | **J3 / TSPU probing**  | 8 active probe types per TLS port — detects Reality/XTLS by silence pattern |
| 7     | **Verdict engine**     | Score 0–100 + detected stack + advice                                      |

#### GeoIP providers (all queried in parallel)

- `ipapi.is` — EU/global, full VPN/proxy/hosting/tor/abuser flags
- `iplocate.io` — EU/global, VPN/proxy/tor flags
- `ip-api.com` — EU, hosting/proxy flags, no API key
- `ipwho.is` — global, HTTPS, no key
- `ipinfo.io` — US/global, ASN + geo
- `freeipapi.com` — EU-based, generous free tier
- `2ip.io` — Russian-hosted, RU-localized

#### UDP handshakes sent

| Port      | Protocol            | Real payload                                    |
|-----------|---------------------|-------------------------------------------------|
| 53        | DNS                 | A query for `example.com`                       |
| 500, 4500 | IKEv2               | 28-byte ISAKMP SA_INIT header                   |
| 1194      | OpenVPN             | `HARD_RESET_CLIENT_V2` (opcode 0x38)            |
| 443       | QUIC v1             | 1200-byte Initial packet (version negotiation)  |
| 51820     | WireGuard           | 148-byte `MessageInitiation` (type=1)           |
| 41641     | Tailscale           | WireGuard-style handshake                       |

#### J3 active probing (8 probes per TLS port)

1. Empty TCP connection (no bytes sent)
2. HTTP `GET /`
3. HTTP `CONNECT example.com:443`
4. SSH client banner
5. Random 512 bytes
6. TLS ClientHello with wrong SNI
7. HTTP absolute-URI request
8. `0xFF × 128` junk bytes

Reality/XTLS silently drops all 8 → diagnostic pattern.
Regular HTTP server replies 400/403 → diagnostic pattern.

#### Verdict scale

| Score    | Label            | Meaning                                                  |
|----------|------------------|----------------------------------------------------------|
| 85–100   | `CLEAN`          | Looks like a normal web server, nothing to flag          |
| 70–84    | `NOISY`          | Some suspicious artifacts, not necessarily VPN           |
| 50–69    | `SUSPICIOUS`     | Several red flags, DPI may pick up                       |
| < 50     | `OBVIOUSLY VPN`  | Trivially detected — you need obfuscation / stack change |

### Install / Usage

#### Windows (pre-built)

Download `byebyevpn-v2.1-win64.zip` from [Releases](../../releases),
extract `byebyevpn.exe` **anywhere**, and run it.

* Single static `.exe` — **no DLLs, no MinGW, no OpenSSL runtime**.
* OpenSSL, libstdc++, libwinpthread are all linked in (≈8 MB).
* Works on Windows 10 1809+ / Windows 11 / Server 2019+.

#### Interactive menu

Double-click `byebyevpn.exe`, or run with no args:

```
[1]  Full scan             — end-to-end scan of an IP/hostname
[2]  TCP port scan         — TCP port-scan only
[3]  UDP probes            — OpenVPN / WireGuard / IKE / QUIC / DNS
[4]  TLS + SNI consistency — TLS audit on a single port (Reality discriminator)
[5]  J3 active probing     — TSPU/GFW-style probes on one port
[6]  GeoIP lookup          — country / ASN / VPN-flag aggregation
[7]  Local analysis        — this machine: VPN adapters, split-tunnel, processes
[0]  Exit
```

#### Command line

```bash
# Full scan (recommended)
byebyevpn <host>
byebyevpn scan 1.2.3.4

# Only a specific phase
byebyevpn ports  my.server.ru
byebyevpn udp    my.server.ru
byebyevpn tls    my.server.ru 443
byebyevpn j3     my.server.ru 443
byebyevpn geoip  8.8.8.8
```

#### Port scan modes

```bash
byebyevpn --full  <host>             # ALL 1–65535 ports (default)
byebyevpn --fast  <host>             # 205 curated VPN/proxy/TLS/admin ports
byebyevpn --range 8000-9000 ports <host>
byebyevpn --ports 80,443,8443 ports <host>
```

#### Tuning

```
--threads N       parallel TCP connects     (default 500)
--tcp-to MS       TCP connect timeout       (default 800)
--udp-to MS       UDP recv timeout          (default 900)
--no-color        disable ANSI colors
-v / --verbose    verbose
```

On slow/laggy networks bump timeout, on fast bump threads:

```bash
byebyevpn --threads 1000 --tcp-to 500 1.2.3.4   # fast LAN
byebyevpn --threads 200  --tcp-to 2500 1.2.3.4  # bad link
```

### Build from source

#### Linux (via Wine — works today)

The v2.1 source is Windows-only (uses `winsock2`, `iphlpapi`, `winhttp`,
`tlhelp32`), so the native Linux build isn't wired up yet. Fastest way to
run it on Linux / macOS right now is through Wine — it's pure user-space,
no kernel bits needed:

```bash
# Debian/Ubuntu
sudo apt install -y wine64

# Arch
sudo pacman -S --needed wine

# Fedora
sudo dnf install -y wine

# Alpine
sudo apk add wine
```

Then grab the release exe and launch it:

```bash
wget https://github.com/pwnnex/byebyevpn/releases/latest/download/byebyevpn-v2.1-win64.zip
unzip byebyevpn-v2.1-win64.zip
wine byebyevpn.exe --fast 1.1.1.1
wine byebyevpn.exe my.server.ru
```

Everything that doesn't touch the local machine (scan / ports / udp / tls /
j3 / geoip) works identically. Only `byebyevpn local` (enumerating host
adapters & processes) depends on being inside a real Windows userland.

#### Linux (cross-build the Windows .exe from Linux)

If you'd rather produce `byebyevpn.exe` on a Linux box (CI, Docker, etc.),
install the MinGW-w64 cross-compiler and build OpenSSL statically for
Windows once:

```bash
# Debian/Ubuntu
sudo apt install -y mingw-w64 wine64

# Arch
sudo pacman -S --needed mingw-w64-gcc mingw-w64-openssl

# Fedora
sudo dnf install -y mingw64-gcc-c++ mingw64-openssl-static
```

Then:

```bash
git clone https://github.com/pwnnex/byebyevpn.git && cd byebyevpn
# Arch / Fedora ship static mingw OpenSSL at a well-known path —
# adjust OSSL_DIR for your distro if needed.
x86_64-w64-mingw32-g++ -O2 -std=c++20 -D_WIN32_WINNT=0x0A00 \
    -static -static-libgcc -static-libstdc++ \
    src/byebyevpn.cpp -o byebyevpn.exe \
    -lssl -lcrypto -lwinpthread \
    -lws2_32 -liphlpapi -lwinhttp -lcrypt32 -lbcrypt -ldnsapi \
    -luser32 -ladvapi32
wine byebyevpn.exe help            # smoke test
```

#### Linux (native build)

Not supported on this branch yet. The code uses `iphlpapi` /
`tlhelp32` / `winhttp` directly; a port to POSIX sockets + libcurl + /proc
is on the roadmap. Patches welcome — the TLS / J3 / UDP-probe modules are
already OS-agnostic (they go straight to OpenSSL + BSD sockets-shaped
APIs), so the work is in:

* `geo_*()` functions (currently WinHTTP) — swap for libcurl or raw
  TLS + OpenSSL on top of the existing `tls_probe()`.
* `list_local_adapters()` / `list_local_routes()` / `list_vpn_processes()`
  — rewrite via `getifaddrs(3)`, `/proc/net/route`, `/proc/<pid>/comm`.
* Replace the `<winsock2.h>` include with a small `#ifdef _WIN32` shim.

#### Windows (prebuilt zip — recommended for end users)

Just grab `byebyevpn-v2.1-win64.zip` from [Releases](../../releases) — it's
a single static `.exe`, no toolchain needed.

#### Windows (MinGW-w64 UCRT — build it yourself)

1. Install MSYS2 and pull the ucrt64 OpenSSL package:

   ```bash
   pacman -S --needed mingw-w64-ucrt-x86_64-gcc \
                       mingw-w64-ucrt-x86_64-openssl \
                       mingw-w64-ucrt-x86_64-make
   ```

2. Build the **standalone static `.exe`** (this is what the release ships):

   ```bash
   make windows-static
   ```

   Under the hood:

   ```bash
   g++ -O2 -std=c++20 -D_WIN32_WINNT=0x0A00 \
       -I/c/msys64/ucrt64/include \
       -static -static-libgcc -static-libstdc++ \
       src/byebyevpn.cpp -o byebyevpn.exe \
       /c/msys64/ucrt64/lib/libssl.a \
       /c/msys64/ucrt64/lib/libcrypto.a \
       /c/msys64/ucrt64/lib/libwinpthread.a \
       -lws2_32 -liphlpapi -lwinhttp -lcrypt32 -lbcrypt -ldnsapi -luser32 -ladvapi32
   ```

3. Produce a release zip (`byebyevpn-win64.zip` = exe + LICENSE + README):

   ```bash
   make release-zip
   ```

Alternatively, build a **dynamic** Windows binary (needs the two OpenSSL
DLLs sitting next to `byebyevpn.exe`):

```bash
make windows
```

#### Windows (MSVC + vcpkg)

```powershell
vcpkg install openssl:x64-windows
cmake -B build -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Release
```

### Limitations

- **Connect-scan, not SYN-scan.** No raw sockets / no admin required,
  but firewalls see a full TCP handshake.
- **Cloudflare WARP / corporate proxy / CGNAT middlebox** can ACK every
  port with identical RTT → tool auto-detects this (>60 open ports with
  RTT variance < 80 ms) and warns "disable WARP, results are fake".
- **Not a DoS.** Full 1–65535 scan sends ~65k TCP packets over
  60–90 seconds at default settings. Curated `--fast` sends ~230.
- **QUIC** — OpenSSL can't derive custom QUIC initial keys; the probe
  only verifies UDP/443 liveness via version negotiation.
- **SNI consistency ≠ Reality.** Modern CDNs also serve wildcard certs
  for any SNI. Combine with J3 probing pattern for confident detection.
- **UDP closed vs filtered** — Windows returns `WSAECONNRESET` on ICMP
  port-unreachable (`closed`); if firewall drops silently you get `no-reply`.
- **GeoIP false positives** — `ipapi.is` flags any hosting IP as VPN.
  Cross-check with behavior, not just flags.

### FAQ

**Q: Do I need to connect to my VPN before scanning?**
A: No. In fact, you shouldn't — you'd be scanning the VPN's exit, not
your target. Run with a clean connection.

**Q: Will this work as "how my ISP / TSPU sees the server"?**
A: Yes, if you run it from regular home internet without any proxy/VPN.
That's exactly the TSPU vantage point.

**Q: Can it detect Reality?**
A: Yes, by combination: silent-on-junk + responds to valid TLS + same cert
across SNIs. Not 100 % but same pattern TSPU uses.

**Q: My Reality server scores low — why?**
A: Usually a duplicate hidden port (`:8443`, `:2053`, etc.) gives away the
pattern. Reality should be on one port, duplicates reveal the stack.

---

## Русский

### Что делает

Семь фаз, все запускаются **с твоей машины** против target IP/хостнейма.
К VPN target'а **подключаться не надо** — тулза сканит его как внешний
наблюдатель, ровно как это делает провайдер / TSPU / DPI.

| Фаза | Модуль                        | Что конкретно делает                                                           |
|------|-------------------------------|--------------------------------------------------------------------------------|
| 1    | **DNS resolve**               | A + AAAA резолв с таймингом                                                    |
| 2    | **GeoIP** (7 источников)      | Страна, ASN, флаги: hosting / VPN / proxy / Tor / abuser — параллельно         |
| 3    | **TCP port scan**             | Connect-scan 1–65535 (дефолт) или 205 curated-портов, 500 потоков, banner-grab |
| 4    | **UDP probes**                | Настоящие handshake-payload'ы на DNS / IKE / OpenVPN / QUIC / WireGuard / Tailscale |
| 5    | **Service fingerprint**       | SSH banner, HTTP probe, TLS handshake + SNI consistency, SOCKS5, CONNECT, SS   |
| 6    | **J3 / TSPU probing**         | 8 типов активных probe'ов на каждый TLS-порт — детектит Reality/XTLS           |
| 7    | **Verdict engine**            | Score 0–100 + определение стека + советы что чинить                            |

#### GeoIP-провайдеры (все параллельно)

- `ipapi.is` — EU/global, полный набор флагов VPN/proxy/hosting/tor/abuser
- `iplocate.io` — EU/global, флаги VPN/proxy/tor
- `ip-api.com` — EU, флаги hosting/proxy, без API-ключа
- `ipwho.is` — global, HTTPS, без ключа
- `ipinfo.io` — US/global, ASN + гео
- `freeipapi.com` — EU, щедрый free tier
- `2ip.io` — Russian-hosted, RU-локализация

#### UDP-handshake'и

| Порт       | Протокол             | Реальный payload                                     |
|------------|----------------------|------------------------------------------------------|
| 53         | DNS                  | A-запрос `example.com`                               |
| 500, 4500  | IKEv2                | 28-байтный ISAKMP SA_INIT header                     |
| 1194       | OpenVPN              | `HARD_RESET_CLIENT_V2` (opcode 0x38)                 |
| 443        | QUIC v1              | 1200-байтный Initial-пакет (version negotiation)     |
| 51820      | WireGuard            | 148-байтный `MessageInitiation` (type=1)             |
| 41641      | Tailscale            | WireGuard-style handshake                            |

#### J3 active probing (8 probe'ов на каждый TLS-порт)

1. Пустой TCP (ничего не шлём)
2. HTTP `GET /`
3. HTTP `CONNECT example.com:443`
4. SSH-клиентский баннер
5. Random 512 байт
6. TLS ClientHello с чужим SNI
7. HTTP absolute-URI
8. `0xFF × 128` мусор

Reality/XTLS молчит на все 8 → диагностический паттерн.
Обычный HTTP-сервер отвечает 400/403 → диагностический паттерн.

#### Шкала verdict

| Score    | Label            | Смысл                                                         |
|----------|------------------|---------------------------------------------------------------|
| 85–100   | `CLEAN`          | Выглядит как обычный веб-сервер, палить нечего                |
| 70–84    | `NOISY`          | Есть подозрительные артефакты, но не факт что VPN             |
| 50–69    | `SUSPICIOUS`     | Несколько красных флагов, DPI может зацепиться                |
| < 50     | `OBVIOUSLY VPN`  | Палится сразу, нужна обфускация / смена стека                 |

### Установка / использование

#### Windows (готовый бинарь)

Скачай релиз, распакуй. В папке должно быть:

```
byebyevpn.exe
libssl-3-x64.dll
libcrypto-3-x64.dll
```

Запускай. Зависимостей кроме OpenSSL DLL — нет.

#### Интерактивное меню

Двойной клик по `byebyevpn.exe` или запуск без аргументов:

```
[1]  Full scan             — полный прогон на IP/hostname
[2]  TCP port scan         — только TCP-порты
[3]  UDP probes            — OpenVPN/WG/IKE/QUIC/DNS
[4]  TLS + SNI consistency — аудит одного TLS-порта (Reality detect)
[5]  J3 active probing     — TSPU-style probe на выбранный порт
[6]  GeoIP lookup          — страна/ASN/VPN-флаги из 7 источников
[0]  Exit
```

#### Командная строка

```bash
# Полный скан (рекомендую)
byebyevpn <host>
byebyevpn scan 1.2.3.4

# Только одна фаза
byebyevpn ports  my.server.ru
byebyevpn udp    my.server.ru
byebyevpn tls    my.server.ru 443
byebyevpn j3     my.server.ru 443
byebyevpn geoip  8.8.8.8
```

#### Режимы port scan

```bash
byebyevpn --full  <host>             # ВСЕ 1–65535 порты (дефолт)
byebyevpn --fast  <host>             # 205 curated VPN/proxy/TLS/admin портов
byebyevpn --range 8000-9000 ports <host>
byebyevpn --ports 80,443,8443 ports <host>
```

#### Опции производительности

```
--threads N       параллельных TCP-connect'ов  (default 500)
--tcp-to MS       TCP connect timeout           (default 800)
--udp-to MS       UDP recv timeout              (default 900)
--no-color        без ANSI-цветов
-v / --verbose    подробный вывод
```

На медленном линке — бумпни timeout, на быстром — бумпни threads:

```bash
byebyevpn --threads 1000 --tcp-to 500 1.2.3.4   # быстрый LAN
byebyevpn --threads 200  --tcp-to 2500 1.2.3.4  # плохой канал
```

### Сборка из исходников

#### Linux через Wine (работает сразу)

Исходник v2.1 пока только под Windows (использует `winsock2`, `iphlpapi`,
`winhttp`, `tlhelp32`), поэтому нативной Linux-сборки сейчас нет. Самый
быстрый способ запустить на Linux / macOS — через Wine, никаких прав root
или kernel-модулей не требуется:

```bash
# Debian/Ubuntu
sudo apt install -y wine64

# Arch
sudo pacman -S --needed wine

# Fedora
sudo dnf install -y wine

# Alpine
sudo apk add wine
```

Дальше скачиваешь релизный exe и запускаешь:

```bash
wget https://github.com/pwnnex/byebyevpn/releases/latest/download/byebyevpn-v2.1-win64.zip
unzip byebyevpn-v2.1-win64.zip
wine byebyevpn.exe --fast 1.1.1.1
wine byebyevpn.exe my.server.ru
```

Все функции, которые не трогают локальную машину (scan / ports / udp /
tls / j3 / geoip) работают один в один. Только `byebyevpn local`
(перечисление адаптеров и процессов) требует настоящего Windows.

#### Linux (кросс-компиляция Windows .exe)

Если нужно собрать `byebyevpn.exe` на Linux-коробке (CI, Docker и т.д.),
ставишь MinGW-w64 и статический OpenSSL под Windows:

```bash
# Debian/Ubuntu
sudo apt install -y mingw-w64 wine64

# Arch
sudo pacman -S --needed mingw-w64-gcc mingw-w64-openssl

# Fedora
sudo dnf install -y mingw64-gcc-c++ mingw64-openssl-static
```

Собираешь:

```bash
git clone https://github.com/pwnnex/byebyevpn.git && cd byebyevpn
x86_64-w64-mingw32-g++ -O2 -std=c++20 -D_WIN32_WINNT=0x0A00 \
    -static -static-libgcc -static-libstdc++ \
    src/byebyevpn.cpp -o byebyevpn.exe \
    -lssl -lcrypto -lwinpthread \
    -lws2_32 -liphlpapi -lwinhttp -lcrypt32 -lbcrypt -ldnsapi \
    -luser32 -ladvapi32
wine byebyevpn.exe help            # smoke-test
```

#### Linux (нативная сборка)

На этой ветке пока не поддерживается. Код напрямую вызывает
`iphlpapi` / `tlhelp32` / `winhttp`; порт на POSIX-сокеты + libcurl +
/proc — в планах. PR приветствуются: TLS / J3 / UDP-probe модули уже
OS-независимые (сразу OpenSSL + BSD-подобные сокеты), переписать надо:

* `geo_*()` (сейчас WinHTTP) — на libcurl или на сыром TLS поверх
  существующего `tls_probe()`.
* `list_local_adapters()` / `list_local_routes()` /
  `list_vpn_processes()` — через `getifaddrs(3)`, `/proc/net/route`,
  `/proc/<pid>/comm`.
* Вместо `<winsock2.h>` поставить маленький `#ifdef _WIN32`-шим.

#### Windows (готовый zip — для обычных юзеров)

Скачиваешь `byebyevpn-v2.1-win64.zip` из [Releases](../../releases) —
это один статический `.exe`, никакой тулчейн не нужен.

#### Windows (MinGW-w64 UCRT — собираешь сам)

1. Поставь MSYS2 и вытащи ucrt64 OpenSSL:

   ```bash
   pacman -S --needed mingw-w64-ucrt-x86_64-gcc \
                       mingw-w64-ucrt-x86_64-openssl \
                       mingw-w64-ucrt-x86_64-make
   ```

2. Собери **standalone статический `.exe`** (это то, что в релизе):

   ```bash
   make windows-static
   ```

   Под капотом:

   ```bash
   g++ -O2 -std=c++20 -D_WIN32_WINNT=0x0A00 \
       -I/c/msys64/ucrt64/include \
       -static -static-libgcc -static-libstdc++ \
       src/byebyevpn.cpp -o byebyevpn.exe \
       /c/msys64/ucrt64/lib/libssl.a \
       /c/msys64/ucrt64/lib/libcrypto.a \
       /c/msys64/ucrt64/lib/libwinpthread.a \
       -lws2_32 -liphlpapi -lwinhttp -lcrypt32 -lbcrypt -ldnsapi -luser32 -ladvapi32
   ```

3. Собери zip для релиза (`byebyevpn-win64.zip` = exe + LICENSE + README):

   ```bash
   make release-zip
   ```

Или **динамическая** Windows-сборка (нужны две OpenSSL DLL рядом с exe):

```bash
make windows
```

#### Windows (MSVC + vcpkg)

```powershell
vcpkg install openssl:x64-windows
cmake -B build -DCMAKE_TOOLCHAIN_FILE=<vcpkg>/scripts/buildsystems/vcpkg.cmake
cmake --build build --config Release
```

### Что детектим

- **Reality / XTLS** — паттерн «молчит на любой мусор, отвечает только на
  валидный TLS» + одинаковый cert на разных SNI + наличие скрытого TLS-порта
- **VLESS / Trojan / Shadowsocks** — silent-on-junk на нестандартных портах
- **OpenVPN** — UDP/1194 + ответ на `HARD_RESET` handshake
- **WireGuard / Amnezia** — UDP handshake-reply с сигнатурой
- **IKEv2 / L2TP / PPTP** — классические VPN-порты + handshake
- **SOCKS5 / HTTP proxy** — открытые 1080/3128/8080 с нормальным greeting'ом
- **Cloudflare WARP / middlebox перехват** — если >60 портов открыто с
  одинаковым RTT, тулза выводит warning «отключи WARP, результаты фейк»

### Пример вывода

```
[1/7] DNS resolve
  my.vpn.server  ->  203.0.113.45  [v4, 12ms]

[2/7] GeoIP  (7 providers in parallel)
  ipapi.is      IP 203.0.113.45   DE (Frankfurt)  AS 16509 Amazon
                flags: HOSTING
  iplocate.io   IP 203.0.113.45   DE (Frankfurt)  AS 16509 Amazon
  ip-api.com    IP 203.0.113.45   DE (Frankfurt)  AS 16509 Amazon
                flags: HOSTING
  ipwho.is      IP 203.0.113.45   DE (Frankfurt)  AS 16509 Amazon
  ipinfo.io     IP 203.0.113.45   DE (Frankfurt)  AS 16509
  freeipapi.com IP 203.0.113.45   DE (Frankfurt)  AS -
  2ip.io (RU)   IP 203.0.113.45   DE (Франкфурт)  AS 16509

[3/7] TCP port scan  mode=FULL 1-65535  (65535 ports, 500 threads, 800ms timeout)
  scanning 65535/65535  open=3
  :22       14ms  SSH
  :443      18ms  HTTPS / XTLS / Reality
  :8443     19ms  HTTPS alt / Reality

[4/7] UDP probes
  UDP:443   QUIC v1 Initial       no answer / filtered

[5/7] Service fingerprints per open port
  :22   SSH            SSH-2.0-OpenSSH_9.2p1
  :443  TLS            TLSv1.3 / TLS_AES_128_GCM_SHA256 / ALPN=h2 / X25519
                       cert: www.microsoft.com  issuer: Microsoft
                       SNI consistency: same cert for ALL alt SNIs -> Reality/XTLS
  :8443 unknown        silent on connect (SS/Trojan/Reality wrapper)

[6/7] J3 / TSPU active probing
  -> port :443
     SILENT   empty
     SILENT   HTTP GET
     SILENT   random 512B
     RESP     valid TLS ClientHello
     pattern: silently drops everything except valid TLS → Reality

[7/7] Verdict
  Score: 38 / 100   OBVIOUSLY VPN
  Stack:  Reality + nginx front
  Advice: SNI-маскировка работает, но duplicate-порт :8443 палит
          паттерн. Либо убери дубль, либо поставь реальный HTTP на :8443.
```

### Лицензия

MIT

### Контрибьют

PR welcome. Особенно интересно:

- Новые VPN-сигнатуры (Hysteria, TUIC, custom Amnezia)
- Улучшение J3-probe'ов (ClientHello fingerprint variance)
- Парсинг реальных QUIC Initial (derived keys)
- Linux/macOS тестирование
- Дополнительные RU/CN GeoIP-источники

В issue приложи `byebyevpn -v <host>` output — поможет улучшить verdict engine.
