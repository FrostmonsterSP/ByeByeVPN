# Changelog

## v2.3 — 2026-04-19

v2.3 is a ground-up rework of the verdict engine in two movements:
first a **calibration pass** that stopped v2.2 from flagging every
cloud-hosted server as suspicious, then a **deep-audit pass** that
re-introduces hard signals — but only ones a legitimate web origin
literally cannot produce.

### Part 1 — calibrated signal model (v2.2 regression fix)

v2.2 went too hard on accumulative red-flagging: any cloud-hosted public
server ended up in the 60–75 range ("NOISY"), because hosting-ASN by
itself was worth a penalty, a single open :443 port was worth a penalty,
and single-source GeoIP VPN tags were counted as evidence. Real TSPU /
GFW classifiers don't work that way — they grade a destination by what
its IP actually does **on the wire** (TLS handshake bytes, cert steering,
reactions to junk, default-port replies). The IP's reputation is at most
a coarse pre-filter.

v2.3 rebalances:

* **Hosting-ASN is no longer a red flag.** Almost every public server on
  the Internet is on a hosting / datacenter ASN. It now appears in a
  new **Informational `[i]`** section with no score impact, and drives
  a concrete hardening suggestion (prefer residential / mobile / CDN
  egress if you're trying to blend in).
* **Single open :443 port is no longer a red flag.** Normal
  reverse-proxies and corporate VLESS-Reality fronts look exactly like
  that. Still shown under Informational, with advice to mirror additional
  TLS ports (8443 / 2053 / 2083 / 2087 / 2096) if the profile looks too
  thin.
* **Single-source GeoIP VPN/proxy tags demoted.** One source out of
  nine calling an IP "VPN" is close to noise. Only a ≥2-source
  consensus now counts as a hard signal.
* **ALPN ≠ h2**, **KEX ≠ X25519**, **IKE control ports open**,
  **country-code mismatch across GeoIPs**, **zero-SAN cert** — all moved
  to Informational, each with its own matching hardening suggestion.
* **Fresh cert (<14d) is now conditional.** Only penalises in
  combination with a sparse hosting-ASN :443 profile; isolated fresh
  certs are normal Let's Encrypt rotation.
* **Blanket COMBO penalty removed.** v2.2 took an extra hit for any 3+
  / 5+ soft flags; with hosting-ASN moved out, this over-counted.

### Part 2 — deep-audit signals (the ones TSPU/GFW actually use)

The calibration pass above made v2.3 gentler on corporate web hosts,
but it also made it too gentle on real Xray installs. A real-world
Reality-static setup on `185.92.181.205` (US / CGI-GLOBAL hosting,
`CN=www.amazon.com` on a random VPS, :2096 returning `HTTP/0.0 307`
with identical byte-exact canned replies) would otherwise have scored
**93/100 CLEAN** — exactly the kind of DPI-evadable setup the tool
should catch.

So v2.3 also adds **hard signals** that are *expensive to fake* —
signals a legitimate web origin literally cannot produce:

**1. Cert impersonation (brand CN on non-owning ASN).**
Reality-static setups point `dest=` at a famous brand (amazon / microsoft
/ apple / google / cloudflare / yandex / github / …) and the server
returns that brand's cert. The tool now builds a 27-entry brand table,
matches the cert CN/SAN against it, and cross-references against the ASN
organisation string from all 9 GeoIP providers. Brand CN on an ASN that
doesn't own the brand = **HIGH** signal. The check runs on the base
(SNI-less) TLS probe and fires even when per-SNI probes return different
certs — that's **Reality in passthrough mode**, where the TLS stream is
transparently tunnelled to the real brand and the real brand then does
its own SNI-based vhost routing. Detecting this is the whole point,
because passthrough-Reality is the stealth-optimised config that
vanilla cert-steering detection (which wanted identical certs across
SNIs) would miss.

Independent confirmation channel: **HTTP `Server:` header brand
mapping.** After TLS handshake we speak HTTP/1.1 and parse the reply.
`Server: CloudFront`, `Server: AmazonS3`, `Server: AWSELB`, `Server:
gws`, `Server: GFE/*`, `Server: Microsoft-IIS/*`, `Server: Yandex*`,
`Server: cloudflare` are only ever emitted by that brand's actual
infrastructure — so the same banner on a non-owner ASN is another
Reality-passthrough tell, counted separately from the TLS-cert channel
in the DPI matrix.

**2. Short-validity cert (<14d total validity).**
Let's Encrypt issues 90d, commercial CAs issue 30–365d. A cert with total
validity under 14 days is never issued by a real CA — it's a hand-rolled
short-lifetime self-signed / test-CA issuance, classic Xray/Trojan
quickfire setup. Flagged **HIGH**.

**3. Active HTTP-over-TLS probe.**
After the TLS handshake we now actually send `GET / HTTP/1.1\r\nHost:…\r\n\r\n`
and parse the reply. New structured detection:
  * `HTTP/0.0` / `HTTP/3.x` text / malformed version = Xray fallback
    stream handler partially decoding a non-protocol request
  * TLS completes but origin sends **0 bytes** back to plain `GET /` =
    stream-layer proxy signature (Xray/Trojan/SS-AEAD)
  * Reply has **no `Server:` header** = middleware tell
    (nginx/Apache/Caddy/CDN always set one)

**4. J3 canned-fallback detection.**
Real web servers vary their replies per request (different URIs →
different statuses). The tool now tracks first-line + byte count across
the 8-probe J3 matrix. Same byte-exact reply for ≥2 different probes
(including at least one valid `GET /`) = static Xray `fallback+redirect`
/ Trojan default page. Flagged **HIGH**. On TLS ports the detection is
gated on the HTTP-over-TLS probe also being anomalous, so a strict nginx
returning uniform 400 to raw-TCP junk is not a false positive.

**5. 3x-ui / x-ui / Marzban panel-port cluster.**
The panel installers preset exactly this TLS-port set:
`2053, 2083, 2087, 2096, 8443, 8880, 6443, 7443, 9443`. Regular web
hosts almost never open this combination together. ≥2 hits = **HIGH**.

**6. Silent-high-port + TLS multipath.**
VLESS on :443 combined with a silent open TLS high port is the classic
Xray multi-inbound layout. Flagged as soft signal.

### New — proxy-middleware detection on the TLS path

v2.1 had a popular signal v2.2 accidentally dropped: a TLS 1.3 endpoint
that handshakes cleanly but **silently drops every HTTP/junk probe** is
almost certainly a stream-layer proxy (Xray / Trojan / Shadowsocks-AEAD)
sitting in front of the origin — a real nginx/Apache would return
`HTTP 400 Bad Request` on non-TLS bytes. v2.3 reintroduces this.

### New — Reality discriminator extended

The SNI consistency test now probes 10 common `dest=` SNIs instead of 4:
adds `bing.com`, `github.com`, `mozilla.org`, `yandex.ru`, plus the
existing amazon/apple/microsoft/google/cloudflare set. The
`cert_impersonation` flag is raised whenever the base cert covers any
famous-brand domain we detect via the brand table, even if we didn't
probe that exact SNI.

### New — 9 GeoIP providers (3 EU / 3 RU / 3 global)

The previous 7-provider stack had one dead endpoint (`2ip.io` → HTTP 429
on every request) and no real RU coverage. v2.3 replaces the stack with
geographically balanced endpoints:

* **EU (3)**: `ipapi.is`, `iplocate.io`, `freeipapi.com`
* **RU (3)**: `2ip.io`/`2ip.me` (fallback chain), `ip-api.com?lang=ru`,
  `sypexgeo.net`
* **Global (3)**: `ip-api.com`, `ipwho.is`, `ipinfo.io`

All 9 queried in parallel; ASN org strings from every successful provider
feed the brand-impersonation cross-check.

### New — DPI exposure matrix expanded to 13 axes

Added four new rows to the matrix:
* **Cert impersonation (Reality-static tell)** — count of ports with
  brand-CN on non-owning ASN
* **Active HTTP-over-TLS probe** — version-anomaly / empty-reply /
  no-Server / looks-real
* **Panel-port cluster (3x-ui/x-ui/Marzban)** — panel hit count
* **J3 canned/anomaly aggregate** — canned/bad-version/raw-non-HTTP
  per-port totals

Existing axes updated:
* **Cert freshness** now escalates to **HIGH** when total validity < 14d
* **Open-port profile** escalates to **HIGH** when dominated by the
  3x-ui preset cluster

### New — Informational section + Hardening suggestions + Threat-model note

The verdict section is split into four blocks:

* **Strong signals `[!]`** — real VPN/proxy evidence (protocol-level
  signature, Reality cert-steering, cert impersonation, canned-fallback,
  short-validity cert, HTTP-version anomaly, 3x-ui cluster, multi-source
  GeoIP consensus, Tor).
* **Soft signals `[-]`** — suggestive patterns that cost a small
  penalty (self-signed cert, expired cert, TLS < 1.3, fresh cert in
  combination with a sparse profile, proxy-middleware on the TLS path,
  silent-high-port + TLS, missing `Server:` header).
* **Informational `[i]`** — pure observation, no penalty, no verdict
  weight. Hosting-ASN, single :443, ALPN, KEX, IKE-ports,
  single-source GeoIP tags, country-code mismatch, zero-SAN all live
  here. Normal public sites can and do produce these.
* **Hardening suggestions** — a concrete, tagged, actionable remedy
  for every observation that could help a censor classify the host
  (`reality-mixed`, `reality-hidden`, `reality-ok`, `proxy-middleware`,
  `reality-multiport`, `openvpn`, `wireguard`, `shadowsocks`, `rdp`,
  `tls-version`, `tls-self-signed`, `port-profile`, `ssh-banner`,
  `cert-fresh`, `asn-hosting`, `threat-intel`,
  `cert-impersonation`, `cert-short-validity`, `canned-fallback`,
  `http-version-anomaly`, `http-silent-origin`,
  `http-missing-server-header`, `xui-panel`).

A final **Threat-model note** is now printed at the end of the verdict,
explaining the principle behind the rebalance — TSPU/GFW grade an IP
by its wire behaviour, not by its reputation, so a VPN front on a
hosting ASN is fine as long as its on-the-wire profile blends in.

### New — stack-identification priority rewritten

Priority order (first match wins):
1. Impersonation + xui-cluster → "Xray-core VLESS+Reality on a 3x-ui panel install"
2. Impersonation only → "Xray-core VLESS+Reality (static dest — cloned brand cert)"
3. Multi-port Reality
4. Reality with HTTP fallback (primary)
5. Reality hidden-mode
6. Generic Reality cert-steering
7. Canned / bad-version → "TLS front + Xray/Trojan stream-layer proxy"
8. Short-validity → "TLS endpoint with hand-rolled short-lifetime cert"
9. 3x-ui cluster only → "3x-ui/x-ui/Marzban panel install"
10. OpenVPN / WireGuard / Shadowsocks / proxy-middleware / generic / none

### Score calibration

Penalties (additive, score starts at 100):
* Cert impersonation: **-22** per port
* J3 canned response: **-18** per port
* Cert short validity: **-15** per port
* HTTP version anomaly: **-14** per port
* 3x-ui panel cluster (≥2 hits): **-14**
* J3 bad HTTP version: **-14**
* Reality cert-steering: **-12**
* HTTP empty response: **-8** per port
* Silent-high-port + TLS: **-7**
* J3 raw non-HTTP: **-7** per port
* HTTP no-Server header: **-5** per port

### Fixed

* `2ip.io` was returning HTTP 429 — replaced with a fallback chain that
  tries `https://2ip.io/geoip/X/` first then `http://api.2ip.me/geo.json?ip=X`.
* `help()` now lists all 9 GeoIP providers grouped by region.
* `geoip` CLI subcommand + interactive-menu option [6] updated to call
  the new 9-provider set (were still on the old 7).

### New — proxy-middleware detection on the TLS path

v2.1 had a popular signal v2.2 accidentally dropped: a TLS 1.3 endpoint
that handshakes cleanly but **silently drops every HTTP/junk probe** is
almost certainly a stream-layer proxy (Xray / Trojan / Shadowsocks-AEAD)
sitting in front of the origin — a real nginx/Apache would return
`HTTP 400 Bad Request` on non-TLS bytes.

v2.3 reintroduces this with a dedicated heuristic:

* Per-port classification now flags
  `TLS endpoint that silently drops all HTTP/junk — proxy/middleware
  in front of origin (Xray/Trojan/SS-AEAD — nginx/Apache would return
  HTTP 400)` when clean TLS + ≥6 silent junk probes and 0 responses.
* When the same kind of port responds with non-HTTP bytes instead of an
  HTTP status line, it's flagged as a custom stream-layer endpoint.
* Either pattern names the stack as
  `TLS front + stream-layer proxy (Xray / Trojan / SS-AEAD)` when it's
  the most specific thing the evidence supports (even without Reality
  cert-steering).

### New — Informational section + Hardening suggestions + Threat-model note

The verdict section is split into four blocks:

* **Strong signals `[!]`** — real VPN/proxy evidence (protocol-level
  signature, Reality cert-steering, multi-source GeoIP consensus, Tor).
* **Soft signals `[-]`** — suggestive patterns that cost a small
  penalty (self-signed cert, expired cert, TLS < 1.3, fresh cert in
  combination with a sparse profile, proxy-middleware on the TLS path).
* **Informational `[i]`** — pure observation, no penalty, no verdict
  weight. Hosting-ASN, single :443, ALPN, KEX, IKE-ports,
  single-source GeoIP tags, country-code mismatch, zero-SAN all live
  here. Normal public sites can and do produce these.
* **Hardening suggestions** — a concrete, tagged, actionable remedy
  for every observation that could help a censor classify the host
  (`reality-mixed`, `reality-hidden`, `reality-ok`, `proxy-middleware`,
  `reality-multiport`, `openvpn`, `wireguard`, `shadowsocks`, `rdp`,
  `tls-version`, `tls-self-signed`, `port-profile`, `ssh-banner`,
  `cert-fresh`, `asn-hosting`, `threat-intel`).

A final **Threat-model note** is now printed at the end of the verdict,
explaining the principle behind the rebalance — TSPU/GFW grade an IP
by its wire behaviour, not by its reputation, so a VPN front on a
hosting ASN is fine as long as its on-the-wire profile blends in.

### Changed — DPI exposure matrix recalibrated

Axes that no longer carry real classification weight on their own:

* `ASN classifier (VPS/hosting)` — most exposures now LOW / NONE.
* `Threat-intel tags (VPN/Proxy/Tor)` — LOW for single-source.
* `Open-port profile (sparsity)` — single :443 now LOW, not MEDIUM.

Axes that matter stay as-is: port-based, protocol handshake, Reality
cert-steering, cert freshness (in combination), J3 junk-probing, TLS
hygiene.

### Build command (unchanged from v2.2)

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

## v2.2 — 2026-04-18

### New — verdict engine is **accumulative** now

v2.1 was too permissive: after rewriting the Reality discriminator the
scoring lost sensitivity to soft signals. Any TLS origin with a single
default cert — including obvious single-purpose VPS fronts — ended up
with 80+/100 and a generic "no VPN signature" verdict.

v2.2 keeps the Reality false-positive fix, but reintroduces
**accumulative red-flagging**:

* **Cert intel.** Each TLS port now surfaces subject CN, issuer CN,
  age-in-days, days-left, SAN count, wildcard/self-signed flags, and
  free-CA detection (Let's Encrypt / ZeroSSL / Buypass / GTS).
* **Red-flag model.** Every soft indicator — hosting-ASN, fresh cert
  (<14d), self-signed cert, expired cert, TLS < 1.3, ALPN != h2,
  KEX != X25519, zero-SAN cert, single-port profile with :443, sparse
  open-port profile on hosting ASN, IKE control ports open,
  single-source VPN/proxy tag, country-code mismatch across GeoIPs —
  adds a soft flag with its own penalty.
* **COMBO penalty.** Three or more independent soft flags trigger an
  extra penalty; five or more trigger a harder one. The pattern as a
  whole starts to look like a single-purpose proxy host even when no
  single signal is conclusive.
* **Strong vs soft signals separated.** `[!]` for strong, `[-]` for
  soft. Counts are shown in the section headers.
* **TLS posture checks now fire per port** (1.3 / h2 / X25519),
  each contributing a soft flag when absent.

### New — DPI exposure matrix

A 9-axis table that spells out by which DPI/classification method the
host can be picked up, and at what level (NONE / LOW / MEDIUM / HIGH):

| Axis                                     | What it checks |
|------------------------------------------|----------------|
| Port-based (default VPN ports)           | 1194/1723/500/4500/51820/… in the open set |
| Protocol handshake signature             | OpenVPN/WG/IKE replies on their wire protocols |
| Cert-steering (Reality discriminator)    | v2.1 Reality test — positive / plain / varies |
| ASN classifier (VPS/hosting)             | how many GeoIP sources flag hosting |
| Threat-intel tags (VPN/Proxy/Tor)        | how many sources put a VPN/Proxy/Tor tag |
| Cert freshness (new-LE watch)            | cert age <14d count |
| Active junk probing (J3)                 | silent-on-junk vs responds-to-junk ratio |
| Open-port profile (sparsity)             | single-port :443 / sparse / diverse |
| TLS hygiene (1.3 + h2 + trusted-CA)      | count of weak-TLS indicators |

### Changed — per-port classification carries cert summary

Each TLS port role now includes TLS version, ALPN, CN, issuer, cert age
and SAN count. Example:

```
  :443   generic HTTPS / CDN origin — TLSv1.3 / ALPN=h2 / CN=*.example.com
         / issuer=R3 / age=42d / SAN=3
```

### Changed — fingerprint line prints cert intel inline

```
  :443   TLS               TLSv1.3 / TLS_AES_128_GCM_SHA256 / ALPN=h2 / X25519 / 87ms
                           cert CN=example.com  issuer=R3  age=42d left=48d  SAN=2 [free-CA]
```

### Fixed

* Scoring was too flat: `hosting` was -5 per source and summed linearly
  with no ceiling. v2.2 splits into hits-counted-once-per-class and adds
  a dedicated COMBO term for >=3/>=5 independent soft flags.
* `single open port = :443 only` is now an explicit soft flag with its
  own penalty, regardless of GeoIP classification.
* Expired certs now contribute a soft flag (v2.1 silently accepted
  them).

### Build command (unchanged from v2.1)

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

## v2.1 — 2026-04-18

### Fixes (false-positive class)

* **Reality discriminator rewrite.** Previous versions flagged any TLS server
  that returned the same cert for every SNI as "Reality/XTLS" — which matched
  the real microsoft.com, every plain nginx default-vhost, and most CDN origins.
  New discriminator:
  1. Same cert returned for ≥3 foreign SNIs (unchanged),
  2. Cert does NOT cover the base SNI (rules out normal TLS hosting),
  3. Cert DOES cover a different foreign SNI (positive Reality steering signal).
  All three must hold. Plain `microsoft.com` → `generic TLS / HTTPS origin`,
  actual Reality with `dest=www.microsoft.com` → `Xray-core (VLESS+Reality)`.
* **J3 silent-on-junk relabelled.** Dropping HTTP/junk before the TLS record
  layer is normal for any strict TLS endpoint; it is no longer rendered as
  "Reality/XTLS-like" in the J3 verdict.
* **Shadowsocks probe softened.** "Accepts junk, never replies" is now
  reported as ambiguous instead of `vpn-like`; the pattern also matches any
  firewalled TCP service.
* **TLS-handshake-failed + silent-on-junk** no longer claims "Reality strict-
  mode" by itself. Reported as ambiguous ("Reality strict / SS-AEAD / Trojan /
  firewall") in the per-port classification with a small score penalty.
* **`pf.tls` is now stored on handshake failure** too, so the verdict engine
  can distinguish "TLS attempted and failed" from "no TLS attempted here".

### Changes (output)

* Entire `[7/7] Verdict` section rewritten: technical English tone, strict
  protocol-level stack naming ("no VPN protocol signature identified" is now
  a valid conclusion), per-port role table, numbered recommendation flags
  (`[!]` / `[+]` / `[-]` / `[i]`).
* SNI consistency output now prints one of four explicit states:
  `Reality/XTLS pattern` / `plain server (single default cert)` /
  `identical cert, covers no foreign SNI (inconclusive)` / `cert varies per
  SNI (multi-tenant TLS)`.
* Interactive menu, help text, and the entire `byebyevpn local` module are
  now in English.
* Scoring tuned: Reality detection now costs a small penalty (being
  identifiable as Reality is itself a detection surface), plain TLS with a
  default cert costs nothing.

### Build / packaging

* **Single-file static Windows release.** `byebyevpn.exe` is now 8 MB and
  has zero runtime dependencies: OpenSSL, libgcc, libstdc++, libwinpthread
  are all statically linked. No more `libssl-3-x64.dll` / `libcrypto-3-x64.dll`
  / MinGW sidecar DLLs next to the executable.
* New `make windows-static` target. Produces the truly standalone `.exe`.
* New `make release-zip` target. Builds and zips `byebyevpn.exe` + `LICENSE`
  + `README.md` into `byebyevpn-win64.zip`.

### Build command (Windows, MinGW-w64 UCRT)

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

## v2.0 — initial public release

* 7 GeoIP providers in parallel.
* Full 1–65535 TCP scan (default) with configurable port modes.
* UDP protocol probes: OpenVPN HARD_RESET, WireGuard handshake, IKEv2, QUIC,
  Tailscale, DNS.
* J3 / TSPU-style active probing suite.
* `byebyevpn local` — local-host VPN posture (adapters, routes, split-tunnel,
  VPN processes + installed config dirs).
* Interactive menu, CLI sub-commands, verdict engine with per-port role
  classification.
