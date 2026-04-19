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
   Full TSPU/DPI/VPN detectability scanner   v2.4
```

**Jump to:** [English](#english) · [Русский](#русский)

---

## English

### What it does

Eight-phase pipeline that runs from **your** machine against a target IP/host.
You do **not** need to be connected to the target's VPN — the tool scans it
as an external observer, exactly how an ISP / TSPU / DPI middlebox sees it.
Built from the Russian OCR methodika (§5-10) — every canonical VPN-detection
axis the state-level DPI uses is implemented.

| Phase | Module                              | What it actually does                                                    |
|-------|-------------------------------------|--------------------------------------------------------------------------|
| 1     | **DNS resolve**                     | A + AAAA resolution with timing                                          |
| 2     | **GeoIP** (9 sources)               | Country, ASN, flags: hosting / VPN / proxy / Tor / abuser — in parallel  |
| 3     | **TCP port scan**                   | Connect-scan 1–65535 (default) or 205 curated ports, 500 threads, banner-grab |
| 4     | **UDP probes** (12 protocols)       | Real handshake payloads to DNS / IKE / OpenVPN / QUIC / WireGuard / Tailscale / L2TP / Hysteria2 / TUIC / AmneziaWG |
| 5     | **Service fingerprint + CT + hdrs** | SSH banner, HTTP probe, TLS + SNI consistency, SOCKS5, CONNECT, Shadowsocks, Certificate Transparency lookup (crt.sh), HTTP proxy-chain header leak parsing (§10.2) |
| 6     | **J3 / TSPU probing**               | 8 active probe types per TLS port — detects Reality/XTLS by silence pattern |
| 7     | **SNITCH + trace + SSTP**           | Latency/GeoIP consistency (§10.1), ICMP hop-count anomaly, Microsoft SSTP probe, JA3 advisory |
| 8     | **Verdict + ТСПУ emulation**        | Score 0–100 + detected stack + advice + explicit Russian-DPI 3-tier ruling (block / throttle / allow) |

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
| 1701      | **L2TP**            | Full SCCRQ with mandatory AVPs                  |
| 36712     | **Hysteria2**       | Custom-DCID QUIC v1 Initial                     |
| 8443      | **TUIC v5**         | QUIC v1 Initial                                 |
| 55555     | **AmneziaWG Sx=8**  | 8-byte junk prefix + valid WG init              |
| 51820     | **AmneziaWG Sx=8**  | Two-probe delta: vanilla-WG ≠ Sx=8              |

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

#### ТСПУ / TSPU emulation verdict (v2.4)

Beyond the numeric score, v2.4 prints an explicit **Russian-DPI-class
classifier ruling** that mirrors what a TSPU middlebox would do with
this destination — in real-world operator terminology:

| Tier     | Ruling              | What it means on the wire                           |
|----------|---------------------|-----------------------------------------------------|
| A≥1      | `IMMEDIATE BLOCK`   | Named VPN protocol matched — SYN/handshake dropped  |
| B≥2      | `BLOCK` (cumulative)| ≥2 soft anomalies — classifier trips block threshold|
| B=1      | `THROTTLE / QoS`    | 1 soft anomaly — flagged for monitoring / rate-limit|
| 0        | `PASS / ALLOW`      | No signatures — traffic passes unhindered           |

Each triggered rule is listed by name with its "why", so you see
exactly which protocol / cert / header / latency signature set off
which tier.

#### Methodika compliance matrix

The tool implements every detection axis named in the Russian OCR
методика §5-10:

| Methodika §  | Detection axis                                  | Module                      |
|--------------|-------------------------------------------------|-----------------------------|
| §5 GeoIP     | Reputational DB / ASN / hosting / VPN / Tor     | Phase 2 (9 GeoIP providers) |
| §6.4 Android | ConnectivityManager IS_VPN flag                 | Local analysis (adapter-kw) |
| §7.4 Android | Interface names `tun/tap/wg/utun/ppp/ipsec`     | Local analysis (adapter-kw) |
| §7.6 Routes  | Default-route via VPN adapter / split tunnel    | Local analysis (routes)     |
| §7.7 DNS     | DNS changed to virtual iface / local addr       | Local analysis (DNS iface)  |
| §7.8 Proxy   | Processes (proxychains / tsocks / xray / etc.)  | Local analysis (procs)      |
| §8 Windows   | `GetAdaptersAddresses` / `IF_TYPE_PROP_VIRTUAL` | Local analysis              |
| §10.1 SNITCH | RTT + GeoIP consistency (landmarks)             | Phase 7 (SNITCH + anchors)  |
| §10.2 HTTP   | `Via` / `Forwarded` / `X-Forwarded-For`         | Phase 5 (HTTP header parse) |

### Install / Usage

#### Windows (pre-built — recommended)

1. Download `byebyevpn-v2.4-win64.zip` from [Releases](../../releases).
2. Extract anywhere (e.g. `C:\Tools\` or just your Desktop).
3. Double-click `byebyevpn.exe` for the interactive menu, or run it from
   a terminal with an IP / hostname / `--help`.

That's it. The zip ships ONE file you actually need — `byebyevpn.exe`
(≈8 MB). No DLLs, no OpenSSL runtime, no MinGW sidecars, no .NET, no
VC++ redistributable. The `.exe` is fully statically linked: OpenSSL
3.x, libstdc++, libwinpthread, and the MinGW C runtime are all baked in.

Runtime requirements:

* Windows 10 1809+ / Windows 11 / Server 2019+
* Internet access (for GeoIP, CT-log, crt.sh lookups)
* No admin rights required — all probes run in user-mode sockets

Bypasses corporate AV in most cases (no suspicious API imports) — if
your AV still flags it, the source is in `src/byebyevpn.cpp` and builds
reproducibly with `make windows-static`.

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
[8]  SNITCH latency check  — RTT + GeoIP consistency (methodika §10.1)
[9]  Traceroute            — ICMP hop-count analysis (userland ttl sweep)
[0]  Exit
```

#### Command line

```bash
# Full scan (recommended)
byebyevpn <host>
byebyevpn scan 1.2.3.4
byebyevpn scan my.server.ru              # hostnames work too (v4 auto-preferred)

# Only a specific phase
byebyevpn ports  my.server.ru
byebyevpn udp    my.server.ru
byebyevpn tls    my.server.ru 443
byebyevpn j3     my.server.ru 443
byebyevpn geoip  8.8.8.8
byebyevpn snitch my.server.ru 443        # RTT/GeoIP consistency check
byebyevpn trace  my.server.ru            # hop-count traceroute
```

**IP vs hostname:** you can pass either — the tool resolves the hostname
with `getaddrinfo`, always picks the **IPv4** address as primary (even
if the DNS returned AAAA first), and prints it so you can see which IP
the scan is actually running against. On IPv4-only consumer connections
(common in Russia/CIS) this fixes the "hostname detects nothing, IP
works" symptom — before v2.4, happy-eyeballs DNS order would sometimes
pick an unreachable IPv6 and silently timeout every port probe.

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

The v2.3 source is Windows-only (uses `winsock2`, `iphlpapi`, `winhttp`,
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
wget https://github.com/pwnnex/byebyevpn/releases/latest/download/byebyevpn-v2.3-win64.zip
unzip byebyevpn-v2.3-win64.zip
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

Just grab `byebyevpn-v2.4-win64.zip` from [Releases](../../releases) — it's
a single static `.exe`, no toolchain needed.

#### Windows (MinGW-w64 UCRT — build it yourself)

1. Install MSYS2 and pull the ucrt64 OpenSSL package:

   ```bash
   pacman -S --needed mingw-w64-ucrt-x86_64-gcc \
                       mingw-w64-ucrt-x86_64-openssl \
                       mingw-w64-ucrt-x86_64-make
   ```

   Or just install [WinLibs GCC](https://winlibs.com/) UCRT build +
   Chocolatey's `openssl` (what I use on CI — no MSYS2 needed).

2. Build the **standalone static `.exe`** (this is what ships in Releases):

   ```bash
   make windows-static
   ```

   Under the hood (what the Makefile runs — you can copy/paste this if
   you don't have `make`):

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

   The resulting `byebyevpn.exe` is ≈8 MB and has zero runtime
   dependencies outside of Windows system DLLs — you can run it on
   any fresh Windows 10/11 box.

3. Verify the build is genuinely standalone (should list only
   `ntdll`, `KERNEL32`, `USER32`, `WS2_32`, `IPHLPAPI`, `WINHTTP`,
   `CRYPT32` etc. — all Windows system DLLs, nothing from MinGW/
   MSYS):

   ```bash
   ldd byebyevpn.exe
   ```

4. Produce a release zip (`byebyevpn-v2.4-win64.zip` = exe + LICENSE +
   README + CHANGELOG):

   ```bash
   make release-zip VERSION=v2.4
   ```

Alternatively, build a **dynamic** Windows binary (needs the two OpenSSL
DLLs sitting next to `byebyevpn.exe`) — much smaller exe, not
recommended for end-user distribution:

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

**Восемь фаз**, все запускаются **с твоей машины** против target IP/хостнейма.
К VPN target'а **подключаться не надо** — тулза сканит его как внешний
наблюдатель, ровно как это делает провайдер / ТСПУ / DPI. Реализована
**полная методика Роскомнадзора** (§5-10 OCR-методики) — каждый
канонический признак VPN, который использует государственный DPI.

| Фаза | Модуль                                   | Что конкретно делает                                                                  |
|------|------------------------------------------|---------------------------------------------------------------------------------------|
| 1    | **DNS resolve**                          | A + AAAA резолв с таймингом                                                           |
| 2    | **GeoIP** (9 источников)                 | Страна, ASN, флаги: hosting / VPN / proxy / Tor / abuser — параллельно (EU+RU+global) |
| 3    | **TCP port scan**                        | Connect-scan 1–65535 (дефолт) или 205 curated-портов, 500 потоков, banner-grab        |
| 4    | **UDP probes** (12 протоколов)           | Handshake-payload'ы: DNS/IKE/OpenVPN/QUIC/WireGuard/Tailscale/**L2TP/Hysteria2/TUIC/AmneziaWG** |
| 5    | **Service fingerprint + CT + hdrs**      | SSH banner, HTTP probe, TLS + SNI consistency, SOCKS5, CONNECT, Shadowsocks, **Certificate Transparency lookup (crt.sh)**, **парсинг proxy-заголовков (§10.2)** |
| 6    | **J3 / TSPU probing**                    | 8 типов активных probe'ов на каждый TLS-порт — детектит Reality/XTLS                  |
| 7    | **SNITCH + traceroute + SSTP**           | **Latency/GeoIP consistency (§10.1)**, **ICMP hop-count**, Microsoft SSTP detector, JA3 advisory |
| 8    | **Verdict + эмуляция ТСПУ**              | Score 0–100, определение стека, советы + **явный вердикт как бы его выдал ТСПУ** (3 tier) |

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
| 1701       | **L2TP**             | Полный SCCRQ с mandatory AVPs                        |
| 36712      | **Hysteria2**        | QUIC v1 Initial с custom DCID                        |
| 8443       | **TUIC v5**          | QUIC v1 Initial                                      |
| 55555      | **AmneziaWG Sx=8**   | 8-байт junk-prefix + валидный WG init                |
| 51820      | **AmneziaWG Sx=8**   | 2-пробное сравнение: vanilla-WG ≠ Sx=8 реплай        |

#### Соответствие методике Роскомнадзора (§5-10)

Каждая ось выявления из официальной OCR-методики — реализована:

| Методика §   | Ось выявления                                       | Модуль                       |
|--------------|-----------------------------------------------------|------------------------------|
| §5 GeoIP     | Репутационная БД / ASN / hosting / VPN / Tor        | Фаза 2 (9 GeoIP-провайдеров) |
| §6.4 Android | ConnectivityManager IS_VPN                          | Local analysis (kw адаптеров)|
| §7.4 Android | Имена интерфейсов `tun/tap/wg/utun/ppp/ipsec`       | Local analysis (kw адаптеров)|
| §7.6 Routes  | Default-route через VPN-адаптер / split tunnel      | Local analysis (routes)      |
| §7.7 DNS     | DNS изменён на виртуальный интерфейс / локальный    | Local analysis (DNS iface)   |
| §7.8 Proxy   | Процессы (proxychains / tsocks / xray / clash ...)  | Local analysis (процессы)    |
| §8 Windows   | `GetAdaptersAddresses` / `IF_TYPE_PROP_VIRTUAL`     | Local analysis               |
| **§10.1**    | **SNITCH — RTT + GeoIP consistency (landmarks)**    | **Фаза 7 (SNITCH + anchors)**|
| **§10.2**    | **HTTP-заголовки `Via` / `Forwarded` / `XFF`**      | **Фаза 5 (HTTP header parse)**|

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

#### Вердикт ТСПУ (v2.4)

Помимо числового score, v2.4 выводит явный **вердикт в стиле российского
государственного DPI** — 3-tier классификацию, как это делает ТСПУ
на продакшн-линиях:

| Tier     | Вердикт             | Что происходит с трафиком                             |
|----------|---------------------|-------------------------------------------------------|
| A≥1      | `IMMEDIATE BLOCK`   | Named VPN-сигнатура — SYN/handshake сразу дропается   |
| B≥2      | `BLOCK` (cumul.)    | ≥2 soft-аномалии — классификатор пересекает порог     |
| B=1      | `THROTTLE / QoS`    | 1 soft-аномалия — мониторинг / rate-limit             |
| 0        | `PASS / ALLOW`      | Нет сигнатур — трафик проходит без вмешательства      |

Каждое сработавшее правило выводится с описанием — видно, какие
конкретно признаки (protocol / cert / header / latency) привели к
классификации.

### Установка / использование

#### Windows (готовый бинарь — рекомендую)

1. Скачай `byebyevpn-v2.4-win64.zip` со страницы [Releases](../../releases).
2. Распакуй в любую папку (`C:\Tools\`, рабочий стол — без разницы).
3. Двойной клик по `byebyevpn.exe` — откроется интерактивное меню.
   Или запусти из терминала: `byebyevpn.exe my.server.ru`.

**Ничего ставить не надо.** В zip лежит ОДИН нужный файл — `byebyevpn.exe`
(≈8 МБ). Никаких DLL, никакого OpenSSL runtime, никакого MinGW, .NET или
VC++ Redistributable. Exe **полностью статический**: OpenSSL 3.x,
libstdc++, libwinpthread и MinGW C runtime зашиты внутрь.

Требования:

* Windows 10 1809+ / Windows 11 / Server 2019+
* Интернет (для GeoIP, Certificate Transparency, crt.sh)
* Прав администратора **не нужно** — всё работает из юзер-мода

#### Интерактивное меню

Двойной клик по `byebyevpn.exe` или запуск без аргументов:

```
[1]  Full scan             — полный прогон на IP/hostname
[2]  TCP port scan         — только TCP-порты
[3]  UDP probes            — OpenVPN/WG/IKE/QUIC/DNS + Hysteria2/TUIC/L2TP/AmneziaWG
[4]  TLS + SNI consistency — аудит одного TLS-порта (Reality discriminator)
[5]  J3 active probing     — TSPU-style probe на выбранный порт
[6]  GeoIP lookup          — страна/ASN/VPN-флаги из 9 источников
[7]  Local analysis        — эта машина: VPN-адаптеры, split-tunnel, процессы
[8]  SNITCH latency check  — RTT + GeoIP consistency (методика §10.1)
[9]  Traceroute            — ICMP hop-count (ttl sweep, userland)
[0]  Exit
```

#### Командная строка

```bash
# Полный скан (рекомендую)
byebyevpn <host>
byebyevpn scan 1.2.3.4
byebyevpn scan my.server.ru              # hostname тоже работает (v4 выбирается авто)

# Только одна фаза
byebyevpn ports  my.server.ru
byebyevpn udp    my.server.ru
byebyevpn tls    my.server.ru 443
byebyevpn j3     my.server.ru 443
byebyevpn geoip  8.8.8.8
byebyevpn snitch my.server.ru 443        # RTT/GeoIP consistency (§10.1)
byebyevpn trace  my.server.ru            # hop-count traceroute
```

**IP или доменное имя — без разницы:** тулза резолвит хостнейм через
`getaddrinfo` и ВСЕГДА выбирает **IPv4** как primary (даже если DNS
вернул AAAA первым). Какой IP реально сканится — печатается в фазе [1/8]
DNS resolve. На IPv4-only подключениях (РФ/СНГ — чаще всего) это чинит
баг "по хосту не детектит, по IP работает": до v2.4 happy-eyeballs мог
выбрать недоступный IPv6 и все пробы тихо таймаутили.

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

Исходник v2.3 пока только под Windows (использует `winsock2`, `iphlpapi`,
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
wget https://github.com/pwnnex/byebyevpn/releases/latest/download/byebyevpn-v2.3-win64.zip
unzip byebyevpn-v2.3-win64.zip
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

Скачиваешь `byebyevpn-v2.4-win64.zip` из [Releases](../../releases) —
внутри **один файл**: `byebyevpn.exe`. Распаковываешь куда угодно,
запускаешь. Никаких DLL, OpenSSL, .NET, VC++ Redistributable или MSYS
ставить НЕ надо.

#### Windows (MinGW-w64 UCRT — собираешь сам)

1. Поставь MSYS2 и вытащи ucrt64 OpenSSL:

   ```bash
   pacman -S --needed mingw-w64-ucrt-x86_64-gcc \
                       mingw-w64-ucrt-x86_64-openssl \
                       mingw-w64-ucrt-x86_64-make
   ```

   Альтернатива: [WinLibs GCC](https://winlibs.com/) UCRT-сборка + OpenSSL
   из Chocolatey (на CI удобнее — без MSYS2).

2. Собери **standalone статический `.exe`** (это то, что в релизе):

   ```bash
   make windows-static
   ```

   Под капотом (одна строка для тех, у кого нет `make`):

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

   На выходе — `byebyevpn.exe` ≈8 МБ без зависимостей от MinGW/MSYS.
   Запускается на любой чистой Windows 10/11.

3. Проверь что сборка реально standalone (должны быть только системные
   DLL: ntdll / KERNEL32 / WS2_32 / WINHTTP / CRYPT32 etc., ничего от
   MinGW/MSYS):

   ```bash
   ldd byebyevpn.exe
   ```

4. Собери релизный zip (`byebyevpn-v2.4-win64.zip` = exe + LICENSE +
   README + CHANGELOG):

   ```bash
   make release-zip VERSION=v2.4
   ```

Или **динамическая** Windows-сборка (нужны две OpenSSL DLL рядом с exe)
— exe сильно меньше, но для раздачи юзерам лучше static:

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

[5/8] Service fingerprints per open port
  :22   SSH            SSH-2.0-OpenSSH_9.2p1
  :443  TLS            TLSv1.3 / TLS_AES_128_GCM_SHA256 / ALPN=h2 / X25519
                       cert: www.microsoft.com  issuer: Microsoft
                       SNI consistency: same cert for ALL alt SNIs -> Reality/XTLS
                       CT-log (crt.sh): cert NOT found — self-signed / forged / LE-staging
  :8443 unknown        silent on connect (SS/Trojan/Reality wrapper)

[6/8] J3 / TSPU active probing
  -> port :443
     SILENT   empty
     SILENT   HTTP GET
     SILENT   random 512B
     RESP     valid TLS ClientHello
     pattern: silently drops everything except valid TLS → Reality

[7/8] SNITCH latency + traceroute + SSTP
  SNITCH RTT:  median=47.3ms  min=43.1ms  max=58.0ms  stddev=5.4ms  (6 samples)
  Anchors:    Cloudflare=30ms  Google=14ms  Yandex=38ms
  Expected:   country=DE  physical_min=25ms  (from RU observer)
  => RTT 47.3ms (stddev 5.4) — consistent with DE geolocation
  Traceroute: 12 hops, reached=yes, max_rtt_jump=18ms
  SSTP/443: not SSTP: HTTP/1.1 400 Bad Request
  Our ClientHello JA3: 0cce74b0d9b7f8528fb2181588d23793 (OpenSSL default)

[8/8] Verdict
  Stack identified:  Xray-core VLESS+Reality (static dest — TLS cert cloned from a major brand)

  ТСПУ / TSPU classification (emulated Russian DPI verdict):
    Verdict: BLOCK (accumulative)  —  ≥2 B-tier anomalies matched
    TSPU-tier hits:  A=0 (protocol block) / B=3 (soft anomaly)
    Triggered rules:
      [B] Reality/XTLS cert-steering             Reality cert-steering pattern detected
      [B] Cert impersonation                     Cert vouches for microsoft.com on non-owning ASN
      [B] CT-log absence                         Cert SHA-256 not found in crt.sh — never publicly logged
    What the operator sees:
      The destination accumulates multiple B-tier anomalies. The classifier
      raises confidence above threshold; the IP gets added to the reputation
      list and future flows are dropped/throttled until the signature changes.

  Score: 38 / 100   OBVIOUSLY VPN
```

### Лицензия

MIT

### Контрибьют

PR welcome. Особенно интересно:

- Парсинг реальных QUIC Initial (derived keys, not just version-neg)
- Настоящая uTLS-Chrome ClientHello генерация через libutls (сейчас только advisory JA3)
- Linux/macOS тестирование и native build
- Дополнительные RU/CN GeoIP-источники
- Расширение brand-table (свои кейсы impersonation)
- Реальный Hysteria2 salamander-decode для port 36712

В issue приложи `byebyevpn -v <host>` output — поможет улучшить verdict engine.
