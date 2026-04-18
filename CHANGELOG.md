# Changelog

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
