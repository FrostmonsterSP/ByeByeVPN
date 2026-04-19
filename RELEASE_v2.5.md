# ByeByeVPN v2.5 — anti-fingerprinting pass

**Tag:** `v2.5`
**Target branch:** `main`
**Commit:** [`04e26cc`](https://github.com/pwnnex/ByeByeVPN/commit/04e26cc)
**Date:** 2026-04-19

This release is a **security / privacy hygiene pass**. There are zero
new features, zero behavioural changes, zero verdict-engine changes.
What changed is the raw bytes the tool emits on the wire.

## TL;DR

v2.4 embedded several identifying patterns into low-level protocol
fields (TLS ClientRandom, QUIC DCID, L2TP Host Name, ICMP payload, SSH
banner, HTTP User-Agent) that were meant as debug-time sentinels but
read as covert fingerprints to anyone auditing the source. v2.5 removes
every single one of them.

After this release:

- **No byte emitted by the tool to any network identifies the tool.**
- Every outbound HTTP request is byte-identical to Chrome 131 on Windows 10.
- Every protocol probe field specified as random is filled with `RAND_bytes()`.
- The only `ByeByeVPN` / `BBVPN` / `pwnnex` strings left in the source tree (3 matches) are the file banner comment, an explanatory comment documenting the scrub, and the CLI `--help` printf. None of them touches a socket.

## Why this release exists

An auditor ([@Dreaght on ntc.party](https://ntc.party/)) pointed out
that the v2.4 code contained a 32-byte field in the TLS ClientHello
probe labelled `// 32 bytes random` which was, in fact, the ASCII
string `RUSSIAN\0BYEBYEVPNACTIVEPROBEJ3\0\0`. He (correctly) framed the
general threat model:

> A backdoored utility distributed to collect user IPs would do exactly
> this — embed a unique marker in outgoing requests so that whoever
> receives them (a censor, or a service operator under subpoena) can
> `grep` the logs of the services the tool hits and enumerate the set
> of source IPs running the tool.

Whether the markers in v2.4 were put there on purpose or by accident is
in the end irrelevant. A scanner that emits a unique outgoing
fingerprint **is** indistinguishable from a user-enumeration honeypot,
so v2.5 simply does not emit one.

Thanks to Dreaght and to everyone else on the ntc.party thread for
catching this before v2.4 had any real distribution.

## Protocol-layer markers removed

| Location | Before | After |
|---|---|---|
| TLS ClientHello ClientRandom (J3 probe #6) | `RUSSIAN\0BYEBYEVPNACTIVEPROBEJ3\0\0` + comment `// 32 bytes random` | `RAND_bytes(32)` per probe |
| QUIC Initial DCID (`quic_probe`) | `0xBB × 8` | `RAND_bytes(8)` per probe |
| Hysteria2 Initial DCID (`hysteria2_probe`) | `0xA1,0xA2,...,0xA8` sequential | `RAND_bytes(8)` per probe |
| L2TP SCCRQ Host Name AVP (`l2tp_probe`) | `BBV` | `lac` (generic L2TP Access Concentrator) |
| ICMP traceroute payload (`trace_hops`) | `ByeByeVPN` (9 bytes) | `abcdefghijklmnopqrstuvwabcdefghi` (32 bytes — Windows `ping.exe` default) |
| J3 SSH banner probe (#4) | `SSH-2.0-ByeByeVPN\r\n` | `SSH-2.0-OpenSSH_8.9p1\r\n` |

## HTTP-layer markers removed

| Location | Before | After |
|---|---|---|
| WinHTTP session name (`http_get`) | `ByeByeVPN/2.5` | `Mozilla/5.0` |
| Outgoing UA (`http_get`) | `Mozilla/5.0 ByeByeVPN` | Chrome 131 on Win10 (full UA string) |
| TLS-HTTP active-probe UA | `Mozilla/5.0 (compatible; ByeByeVPN/2.3)` | Chrome 131 on Win10 |
| Outgoing HTTP headers | `User-Agent`, `Accept: */*` | Full Chrome 131 header set, in browser-correct order |

The full Chrome 131 / Windows 10 header set now emitted on **every**
outbound HTTP request (GeoIP, crt.sh, TLS-HTTP audit probe):

```
User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/131.0.0.0 Safari/537.36
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7
Accept-Language: en-US,en;q=0.9
Accept-Encoding: gzip, deflate, br, zstd
Sec-Fetch-Dest: document
Sec-Fetch-Mode: navigate
Sec-Fetch-Site: none
Sec-Fetch-User: ?1
Upgrade-Insecure-Requests: 1
```

A censor or a third-party log-aggregator has **no** grep-able way to
enumerate scanner users from its access logs.

## Verify it yourself in 30 seconds

```bash
git clone https://github.com/pwnnex/ByeByeVPN.git
cd ByeByeVPN
git checkout v2.5
grep -nE 'ByeByeVPN|BYEBYEVPN|BBVPN|BBV|pwnnex' src/byebyevpn.cpp
```

Expected output (three lines, all non-network):

```
1:     // ByeByeVPN — full VPN / proxy / Reality detectability analyzer
402:   // cannot `grep ByeByeVPN` to enumerate scanner users.
4974:  printf("ByeByeVPN — full TSPU/DPI/VPN detectability scanner\n\n");
```

For protocol-layer audit, see:

- `j3_active_probes()` ~L1781 — TLS ClientRandom via `RAND_bytes(hello + 11, 32)`
- `quic_probe()` ~L1924 — DCID via `RAND_bytes(pkt + 6, 8)`
- `hysteria2_probe()` ~L2795 — DCID via `RAND_bytes(pkt + 6, 8)`
- `l2tp_probe()` ~L2828 — Host Name AVP = `lac`
- `trace_hops()` ~L2698 — ICMP payload = Windows `ping.exe` default
- `http_get()` ~L387 — full Chrome header set

## No behavioural change

Detection logic, verdict engine, signal weights, pipeline phases,
scoring — all identical to v2.4. Running v2.5 against the same target
produces the same verdict.

The test surface on target servers is also the same: DPI still sees
"TLS ClientHello with invalid SNI", "QUIC Initial with unknown DCID",
"L2TP SCCRQ with generic hostname", etc. The byte contents of probes
changed; what those probes **test for** did not.

## Downloads

**`byebyevpn-v2.5-win64.zip`** (≈361 KB) — single self-contained
static `byebyevpn.exe` (≈1.1 MB) + LICENSE + README + CHANGELOG. No
DLLs, no OpenSSL runtime, no MinGW sidecars. Runs on Windows 10 1809+
/ Windows 11 / Server 2019+ out of the box, no admin rights needed.

### SHA256

```
byebyevpn.exe              d608cc75801644e84906c4d314b320fe08ae46a83d0a64c7b8e8a7c4a7f1ad3d
byebyevpn-v2.5-win64.zip   a74e1c41ae69f9048ae53e317119ff3b7b4f729181305c95e02dc826598180f9
```

Verify with:

```powershell
# Windows PowerShell
Get-FileHash byebyevpn.exe -Algorithm SHA256
Get-FileHash byebyevpn-v2.5-win64.zip -Algorithm SHA256
```

```bash
# Linux / macOS
sha256sum byebyevpn.exe byebyevpn-v2.5-win64.zip
```

### Reproducible build

```bash
git clone https://github.com/pwnnex/ByeByeVPN.git
cd ByeByeVPN
git checkout v2.5
make windows-static       # requires MinGW-w64 UCRT + static OpenSSL
sha256sum byebyevpn.exe    # should match the hash above
```

Any binary not matching these hashes is not an official v2.5 build.

## Upgrade path

If you have v2.4 installed: just replace `byebyevpn.exe` with the v2.5
build. Command-line flags, interactive menu, output format — all
unchanged.

## Full changelog

See [CHANGELOG.md](./CHANGELOG.md) `## v2.5 — 2026-04-19` for the full
file-by-file diff and rationale.

---

**Previous release:** [v2.4](https://github.com/pwnnex/ByeByeVPN/releases/tag/v2.4)
