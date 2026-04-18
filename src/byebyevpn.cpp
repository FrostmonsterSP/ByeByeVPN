// ByeByeVPN — full VPN / proxy / Reality detectability analyzer
// ----------------------------------------------------------------------------
// Targets an arbitrary IP or hostname and performs:
//
//   1) DNS resolution + parallel GeoIP aggregation (7 providers, RU + EU).
//   2) TCP port scan — full (1..65535), fast (205 curated ports), ranged or
//      explicit list. Banner grab + service hints on every open port.
//   3) UDP probes: OpenVPN HARD_RESET, WireGuard handshake init, IKEv2 on
//      500/4500, QUIC on 443, Tailscale on 41641, DNS.
//   4) Service fingerprint on every open port:
//        SSH banner, HTTP probe, TLS handshake + SNI-steering test + ALPN,
//        SOCKS5 greet, HTTP CONNECT proxy test, Shadowsocks/Trojan probe,
//        Reality discriminator (cert must cover a foreign SNI), VLESS/XHTTP
//        fallback check.
//   5) J3 / TSPU / GFW-style active-probing suite (8 probes per TLS port).
//   6) TLS fingerprint: version, cipher, ALPN, group, cert subject / issuer /
//      SHA-256 / SAN list.
//   7) Timing analysis: RTT jitter, duplicate-RTT middlebox detection.
//   8) Verdict engine: strict protocol-level stack identification + per-port
//      role classification + technical recommendations.
//
//   Extra: `byebyevpn local` — local-host posture (adapters, routes, split-
//   tunnel detection, running VPN/proxy processes, installed config dirs).
//
// No raw sockets. No admin privileges required.
// Platform: Windows x64, OpenSSL 3.x. Builds as a single static .exe.
//
#define WIN32_LEAN_AND_MEAN
#define _WIN32_WINNT 0x0A00
#define NOMINMAX
#include <winsock2.h>
#include <ws2tcpip.h>
#include <iphlpapi.h>
#include <windows.h>
#include <tlhelp32.h>
#include <winhttp.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/x509.h>
#include <openssl/x509v3.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/rand.h>

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <future>
#include <iostream>
#include <map>
#include <mutex>
#include <optional>
#include <set>
#include <sstream>
#include <string>
#include <thread>
#include <vector>

using std::string;
using std::vector;
using std::optional;
using std::set;

// ============================================================================
// console
// ============================================================================
static bool g_no_color = false;
static bool g_verbose  = false;
static int  g_threads  = 500;
static int  g_tcp_to   = 800;
static int  g_udp_to   = 900;

// port-scan mode
enum class PortMode { FULL, FAST, RANGE, LIST };
static PortMode    g_port_mode = PortMode::FULL;
static int         g_range_lo  = 1;
static int         g_range_hi  = 65535;
static std::vector<int> g_port_list;

namespace C {
    static const char* RST  = "\x1b[0m";
    static const char* BOLD = "\x1b[1m";
    static const char* DIM  = "\x1b[2m";
    static const char* RED  = "\x1b[31m";
    static const char* GRN  = "\x1b[32m";
    static const char* YEL  = "\x1b[33m";
    static const char* BLU  = "\x1b[34m";
    static const char* MAG  = "\x1b[35m";
    static const char* CYN  = "\x1b[36m";
    static const char* WHT  = "\x1b[97m";
}
static const char* col(const char* c) { return g_no_color ? "" : c; }

static void enable_vt() {
    HANDLE h = GetStdHandle(STD_OUTPUT_HANDLE);
    DWORD mode = 0;
    if (GetConsoleMode(h, &mode))
        SetConsoleMode(h, mode | ENABLE_VIRTUAL_TERMINAL_PROCESSING);
    SetConsoleOutputCP(CP_UTF8);
}

static void banner() {
    printf("%s%s", col(C::BOLD), col(C::MAG));
    puts(" ____             ____           __     ______  _   _ ");
    puts("| __ ) _   _  ___| __ ) _   _  __\\ \\   / /  _ \\| \\ | |");
    puts("|  _ \\| | | |/ _ \\  _ \\| | | |/ _ \\ \\ / /| |_) |  \\| |");
    puts("| |_) | |_| |  __/ |_) | |_| |  __/\\ V / |  __/| |\\  |");
    puts("|____/ \\__, |\\___|____/ \\__, |\\___| \\_/  |_|   |_| \\_|");
    puts("       |___/            |___/                          ");
    printf("%s", col(C::RST));
    printf("%s  Full TSPU/DPI/VPN detectability scanner  v2.1%s\n\n",
           col(C::DIM), col(C::RST));
}

// ============================================================================
// util
// ============================================================================
static string tolower_s(string s) {
    for (auto& c: s) c = (char)tolower((unsigned char)c);
    return s;
}
static bool contains(const string& h, const string& n) { return h.find(n) != string::npos; }
static bool starts_with(const string& s, const string& p) {
    return s.size() >= p.size() && std::memcmp(s.data(), p.data(), p.size()) == 0;
}
static string trim(const string& s) {
    size_t a=0,b=s.size();
    while(a<b && isspace((unsigned char)s[a])) ++a;
    while(b>a && isspace((unsigned char)s[b-1])) --b;
    return s.substr(a,b-a);
}
static vector<string> split(const string& s, char sep) {
    vector<string> r; string cur;
    for (char c: s) {
        if (c == sep) { r.push_back(cur); cur.clear(); }
        else cur.push_back(c);
    }
    r.push_back(cur);
    return r;
}
static string hex_s(const unsigned char* d, size_t n, bool spaces = false) {
    static const char* hex = "0123456789abcdef";
    string s; s.reserve(n*(spaces?3:2));
    for (size_t i=0;i<n;++i) {
        s += hex[(d[i]>>4)&0xF]; s += hex[d[i]&0xF];
        if (spaces && i+1<n) s += ' ';
    }
    return s;
}
static string ws2s(const wchar_t* w) {
    if (!w) return {};
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, nullptr, 0, nullptr, nullptr);
    if (n <= 0) return {};
    string s((size_t)n - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, w, -1, s.data(), n, nullptr, nullptr);
    return s;
}
static std::wstring s2ws(const string& s) {
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, nullptr, 0);
    if (n <= 0) return {};
    std::wstring w((size_t)n - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), -1, w.data(), n);
    return w;
}

// JSON scan (plain)
static string json_get_str(const string& body, const string& key) {
    string pat = "\"" + key + "\"";
    size_t p = 0;
    while ((p = body.find(pat, p)) != string::npos) {
        size_t q = p + pat.size();
        while (q < body.size() && (body[q]==' '||body[q]==':'||body[q]=='\t')) ++q;
        if (q >= body.size()) return {};
        if (body[q] == '"') {
            size_t e = q + 1;
            string v;
            while (e < body.size() && body[e] != '"') {
                if (body[e] == '\\' && e+1 < body.size()) { v += body[e+1]; e += 2; }
                else { v += body[e]; ++e; }
            }
            return v;
        } else {
            size_t e = q;
            while (e < body.size() && body[e]!=',' && body[e]!='}' && body[e]!='\n') ++e;
            return trim(body.substr(q, e-q));
        }
    }
    return {};
}

// ============================================================================
// DNS resolve (returns all IPs)
// ============================================================================
struct Resolved {
    string host;
    string primary_ip;
    vector<string> ips;
    string family; // v4 / v6 / mixed
    string err;
    long long ms = 0;
};

static string sa_ip(const sockaddr* sa) {
    char buf[INET6_ADDRSTRLEN] = {0};
    if (sa->sa_family == AF_INET) {
        auto* s4 = (sockaddr_in*)sa;
        InetNtopA(AF_INET, &s4->sin_addr, buf, sizeof(buf));
    } else {
        auto* s6 = (sockaddr_in6*)sa;
        InetNtopA(AF_INET6, &s6->sin6_addr, buf, sizeof(buf));
    }
    return buf;
}

static Resolved resolve_host(const string& host) {
    Resolved r; r.host = host;
    auto t0 = std::chrono::steady_clock::now();
    addrinfo hints{}; hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    addrinfo* ai = nullptr;
    int rc = getaddrinfo(host.c_str(), nullptr, &hints, &ai);
    if (rc != 0) { r.err = gai_strerrorA(rc); return r; }
    bool has4 = false, has6 = false;
    for (auto* p = ai; p; p = p->ai_next) {
        string ip = sa_ip(p->ai_addr);
        if (std::find(r.ips.begin(), r.ips.end(), ip) == r.ips.end())
            r.ips.push_back(ip);
        if (p->ai_family == AF_INET) has4 = true;
        else if (p->ai_family == AF_INET6) has6 = true;
    }
    freeaddrinfo(ai);
    if (!r.ips.empty()) r.primary_ip = r.ips.front();
    r.family = (has4 && has6) ? "mixed" : has4 ? "v4" : "v6";
    r.ms = std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::steady_clock::now() - t0).count();
    return r;
}

// ============================================================================
// TCP connect (non-blocking with timeout)
// ============================================================================
static SOCKET tcp_connect(const string& host, int port, int timeout_ms, string& err) {
    addrinfo hints{}; hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    addrinfo* ai = nullptr;
    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &ai) != 0) {
        err = "dns"; return INVALID_SOCKET;
    }
    SOCKET s = INVALID_SOCKET;
    for (auto* p = ai; p; p = p->ai_next) {
        s = socket(p->ai_family, SOCK_STREAM, IPPROTO_TCP);
        if (s == INVALID_SOCKET) continue;
        u_long nb = 1; ioctlsocket(s, FIONBIO, &nb);
        int rc = connect(s, p->ai_addr, (int)p->ai_addrlen);
        if (rc == 0) { u_long bl=0; ioctlsocket(s,FIONBIO,&bl); break; }
        if (WSAGetLastError() == WSAEWOULDBLOCK) {
            fd_set wr, ex; FD_ZERO(&wr); FD_SET(s, &wr); FD_ZERO(&ex); FD_SET(s, &ex);
            timeval tv{}; tv.tv_sec = timeout_ms/1000; tv.tv_usec = (timeout_ms%1000)*1000;
            int sr = select(0, nullptr, &wr, &ex, &tv);
            if (sr > 0 && FD_ISSET(s, &wr)) {
                int se = 0; int sl = sizeof(se);
                getsockopt(s, SOL_SOCKET, SO_ERROR, (char*)&se, &sl);
                if (se == 0) { u_long bl=0; ioctlsocket(s,FIONBIO,&bl); break; }
            }
        }
        closesocket(s); s = INVALID_SOCKET;
    }
    freeaddrinfo(ai);
    if (s == INVALID_SOCKET) err = "connect";
    return s;
}

// recv with timeout (blocking socket, set SO_RCVTIMEO)
static int tcp_recv_to(SOCKET s, char* buf, int max, int timeout_ms) {
    DWORD to = (DWORD)timeout_ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&to, sizeof(to));
    return recv(s, buf, max, 0);
}
static int tcp_send_all(SOCKET s, const void* data, int n) {
    const char* p = (const char*)data; int left = n;
    while (left > 0) {
        int rc = send(s, p, left, 0);
        if (rc <= 0) return rc;
        p += rc; left -= rc;
    }
    return n;
}

// ============================================================================
// UDP probe
// ============================================================================
struct UdpResult {
    bool    responded = false;
    int     bytes = 0;
    string  reply_hex;       // first 32 bytes hex
    long long ms = 0;
    string  err;
};

static UdpResult udp_probe(const string& host, int port,
                           const unsigned char* payload, int plen,
                           int timeout_ms) {
    UdpResult r;
    auto t0 = std::chrono::steady_clock::now();
    addrinfo hints{}; hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_DGRAM;
    addrinfo* ai = nullptr;
    if (getaddrinfo(host.c_str(), std::to_string(port).c_str(), &hints, &ai) != 0) {
        r.err = "dns"; return r;
    }
    SOCKET s = socket(ai->ai_family, SOCK_DGRAM, IPPROTO_UDP);
    if (s == INVALID_SOCKET) { freeaddrinfo(ai); r.err = "socket"; return r; }
    DWORD to = (DWORD)timeout_ms;
    setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, (char*)&to, sizeof(to));
    int rc = sendto(s, (const char*)payload, plen, 0, ai->ai_addr, (int)ai->ai_addrlen);
    freeaddrinfo(ai);
    if (rc <= 0) { closesocket(s); r.err = "send"; return r; }
    char buf[2048];
    int got = recv(s, buf, sizeof(buf), 0);
    closesocket(s);
    r.ms = std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::steady_clock::now() - t0).count();
    int werr = WSAGetLastError();
    if (got > 0) {
        r.responded = true; r.bytes = got;
        r.reply_hex = hex_s((unsigned char*)buf, std::min(32, got), true);
    } else if (werr == WSAETIMEDOUT || werr == 0) {
        r.err = "no-reply / filtered";
    } else if (werr == WSAECONNRESET) {
        r.err = "ICMP port-unreachable (port closed)";
    } else {
        r.err = "wsa " + std::to_string(werr);
    }
    return r;
}

// ============================================================================
// WinHTTP client (for GeoIP etc)
// ============================================================================
struct HttpResp {
    int status = 0;
    string body;
    string err;
    long long ms = 0;
    bool ok() const { return status >= 200 && status < 400; }
};

static HttpResp http_get(const string& url, int timeout_ms = 7000) {
    HttpResp r;
    auto t0 = std::chrono::steady_clock::now();
    URL_COMPONENTS u{}; u.dwStructSize = sizeof(u);
    wchar_t host[256]={0}, path[1024]={0};
    u.lpszHostName = host; u.dwHostNameLength = 255;
    u.lpszUrlPath = path; u.dwUrlPathLength = 1023;
    std::wstring wurl = s2ws(url);
    if (!WinHttpCrackUrl(wurl.c_str(), 0, 0, &u)) { r.err = "bad url"; return r; }

    HINTERNET hS = WinHttpOpen(L"ByeByeVPN/2.1", WINHTTP_ACCESS_TYPE_AUTOMATIC_PROXY,
                               WINHTTP_NO_PROXY_NAME, WINHTTP_NO_PROXY_BYPASS, 0);
    if (!hS) { r.err = "open"; return r; }
    WinHttpSetTimeouts(hS, timeout_ms, timeout_ms, timeout_ms, timeout_ms);
    HINTERNET hC = WinHttpConnect(hS, host, u.nPort, 0);
    if (!hC) { r.err = "connect"; WinHttpCloseHandle(hS); return r; }
    DWORD flags = (u.nScheme == INTERNET_SCHEME_HTTPS) ? WINHTTP_FLAG_SECURE : 0;
    HINTERNET hR = WinHttpOpenRequest(hC, L"GET", path, nullptr,
                                      WINHTTP_NO_REFERER,
                                      WINHTTP_DEFAULT_ACCEPT_TYPES, flags);
    if (!hR) { r.err = "req"; WinHttpCloseHandle(hC); WinHttpCloseHandle(hS); return r; }
    std::wstring hdrs = L"User-Agent: Mozilla/5.0 ByeByeVPN\r\nAccept: */*\r\n";
    if (!WinHttpSendRequest(hR, hdrs.c_str(), (DWORD)-1L, WINHTTP_NO_REQUEST_DATA, 0, 0, 0) ||
        !WinHttpReceiveResponse(hR, nullptr)) {
        r.err = "io " + std::to_string(GetLastError());
        WinHttpCloseHandle(hR); WinHttpCloseHandle(hC); WinHttpCloseHandle(hS);
        return r;
    }
    DWORD st = 0, sz = sizeof(st);
    WinHttpQueryHeaders(hR, WINHTTP_QUERY_STATUS_CODE | WINHTTP_QUERY_FLAG_NUMBER,
                        nullptr, &st, &sz, nullptr);
    r.status = (int)st;
    for (;;) {
        DWORD avail = 0;
        if (!WinHttpQueryDataAvailable(hR, &avail) || avail == 0) break;
        vector<char> buf(avail);
        DWORD got = 0;
        if (!WinHttpReadData(hR, buf.data(), avail, &got) || got == 0) break;
        r.body.append(buf.data(), got);
        if (r.body.size() > 512*1024) break;
    }
    WinHttpCloseHandle(hR); WinHttpCloseHandle(hC); WinHttpCloseHandle(hS);
    r.ms = std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::steady_clock::now() - t0).count();
    return r;
}

// ============================================================================
// GeoIP
// ============================================================================
struct GeoInfo {
    string ip, country, country_code, city, asn, asn_org;
    bool is_hosting = false, is_vpn = false, is_proxy = false, is_tor = false, is_abuser = false;
    string source;
    string err;
};

static GeoInfo geo_ipapi_is(const string& ip) {
    GeoInfo g; g.source = "ipapi.is";
    string url = "https://api.ipapi.is/";
    if (!ip.empty()) url += "?q=" + ip;
    auto r = http_get(url);
    if (!r.ok()) { g.err = "http " + std::to_string(r.status) + " " + r.err; return g; }
    g.ip           = json_get_str(r.body, "ip");
    g.country      = json_get_str(r.body, "country");
    g.country_code = json_get_str(r.body, "country_code");
    g.city         = json_get_str(r.body, "city");
    string asn_block;
    size_t ap = r.body.find("\"asn\"");
    if (ap != string::npos) {
        size_t ob = r.body.find('{', ap);
        size_t ce = ob == string::npos ? string::npos : r.body.find('}', ob);
        if (ob != string::npos && ce != string::npos)
            asn_block = r.body.substr(ob, ce-ob+1);
    }
    g.asn     = json_get_str(asn_block, "asn");
    g.asn_org = json_get_str(asn_block, "org");
    if (g.asn.empty()) g.asn = json_get_str(r.body, "asn");
    auto t = [&](const char* k){ return json_get_str(r.body, k) == "true"; };
    g.is_hosting = t("is_datacenter") || t("is_hosting");
    g.is_vpn     = t("is_vpn");
    g.is_proxy   = t("is_proxy");
    g.is_tor     = t("is_tor");
    g.is_abuser  = t("is_abuser");
    return g;
}

static GeoInfo geo_iplocate(const string& ip) {
    GeoInfo g; g.source = "iplocate.io";
    string url = "https://iplocate.io/api/lookup/";
    if (!ip.empty()) url += ip;
    auto r = http_get(url);
    if (!r.ok()) { g.err = "http " + std::to_string(r.status) + " " + r.err; return g; }
    g.ip           = json_get_str(r.body, "ip");
    g.country      = json_get_str(r.body, "country");
    g.country_code = json_get_str(r.body, "country_code");
    g.city         = json_get_str(r.body, "city");
    string asn_block;
    size_t ap = r.body.find("\"asn\"");
    if (ap != string::npos) {
        size_t ob = r.body.find('{', ap);
        size_t ce = ob == string::npos ? string::npos : r.body.find('}', ob);
        if (ob != string::npos && ce != string::npos
            && ob < (r.body.find(',', ap) == string::npos ? ce+1 : r.body.find(',', ap)))
            asn_block = r.body.substr(ob, ce-ob+1);
    }
    if (!asn_block.empty()) {
        g.asn     = json_get_str(asn_block, "asn");
        g.asn_org = json_get_str(asn_block, "name");
        if (g.asn_org.empty()) g.asn_org = json_get_str(asn_block, "org");
    } else {
        g.asn     = json_get_str(r.body, "asn");
        g.asn_org = json_get_str(r.body, "org");
    }
    g.is_hosting = json_get_str(r.body, "is_hosting") == "true";
    g.is_vpn     = json_get_str(r.body, "is_vpn") == "true"
                 || json_get_str(r.body, "is_anonymous") == "true";
    g.is_proxy   = json_get_str(r.body, "is_proxy") == "true";
    g.is_tor     = json_get_str(r.body, "is_tor") == "true";
    return g;
}

// ip-api.com  —  EU/global, free, no key (HTTP only on free tier)
static GeoInfo geo_ip_api_com(const string& ip) {
    GeoInfo g; g.source = "ip-api.com";
    string url = "http://ip-api.com/json/";
    if (!ip.empty()) url += ip;
    url += "?fields=status,country,countryCode,city,isp,org,as,asname,hosting,proxy,mobile,query";
    auto r = http_get(url);
    if (!r.ok()) { g.err = "http " + std::to_string(r.status) + " " + r.err; return g; }
    g.ip           = json_get_str(r.body, "query");
    g.country      = json_get_str(r.body, "country");
    g.country_code = json_get_str(r.body, "countryCode");
    g.city         = json_get_str(r.body, "city");
    g.asn          = json_get_str(r.body, "as");
    g.asn_org      = json_get_str(r.body, "isp");
    if (g.asn_org.empty()) g.asn_org = json_get_str(r.body, "org");
    g.is_hosting   = json_get_str(r.body, "hosting") == "true";
    g.is_proxy     = json_get_str(r.body, "proxy")   == "true";
    return g;
}

// ipwho.is  —  global, free, HTTPS, no key
static GeoInfo geo_ipwho_is(const string& ip) {
    GeoInfo g; g.source = "ipwho.is";
    string url = "https://ipwho.is/";
    if (!ip.empty()) url += ip;
    auto r = http_get(url);
    if (!r.ok()) { g.err = "http " + std::to_string(r.status) + " " + r.err; return g; }
    g.ip           = json_get_str(r.body, "ip");
    g.country      = json_get_str(r.body, "country");
    g.country_code = json_get_str(r.body, "country_code");
    g.city         = json_get_str(r.body, "city");
    // connection.asn / connection.isp / connection.org
    size_t cp = r.body.find("\"connection\"");
    if (cp != string::npos) {
        size_t ob = r.body.find('{', cp);
        size_t ce = ob == string::npos ? string::npos : r.body.find('}', ob);
        if (ob != string::npos && ce != string::npos) {
            string sb = r.body.substr(ob, ce-ob+1);
            g.asn     = json_get_str(sb, "asn");
            g.asn_org = json_get_str(sb, "isp");
            if (g.asn_org.empty()) g.asn_org = json_get_str(sb, "org");
        }
    }
    return g;
}

// ipinfo.io  —  global, no-token tier returns country/city/org
static GeoInfo geo_ipinfo_io(const string& ip) {
    GeoInfo g; g.source = "ipinfo.io";
    string url = "https://ipinfo.io/";
    if (!ip.empty()) url += ip;
    url += "/json";
    auto r = http_get(url);
    if (!r.ok()) { g.err = "http " + std::to_string(r.status) + " " + r.err; return g; }
    g.ip           = json_get_str(r.body, "ip");
    g.country_code = json_get_str(r.body, "country");  // ipinfo returns 2-letter only
    g.city         = json_get_str(r.body, "city");
    string orgraw  = json_get_str(r.body, "org");      // e.g. "AS13335 Cloudflare"
    if (!orgraw.empty()) {
        if (orgraw.rfind("AS",0)==0) {
            size_t sp = orgraw.find(' ');
            if (sp != string::npos) {
                g.asn     = orgraw.substr(0, sp);
                g.asn_org = orgraw.substr(sp+1);
            } else g.asn = orgraw;
        } else g.asn_org = orgraw;
    }
    return g;
}

// freeipapi.com  —  EU-based, generous free tier, HTTPS
static GeoInfo geo_freeipapi(const string& ip) {
    GeoInfo g; g.source = "freeipapi.com";
    string url = "https://freeipapi.com/api/json/";
    if (!ip.empty()) url += ip;
    auto r = http_get(url);
    if (!r.ok()) { g.err = "http " + std::to_string(r.status) + " " + r.err; return g; }
    g.ip           = json_get_str(r.body, "ipAddress");
    g.country      = json_get_str(r.body, "countryName");
    g.country_code = json_get_str(r.body, "countryCode");
    g.city         = json_get_str(r.body, "cityName");
    return g;
}

// 2ip.io / api.2ip.me  —  Russian-hosted, widely used RU-side checker
// Endpoint: http://api.2ip.me/geo.json?ip=...  (HTTP, no key needed)
static GeoInfo geo_2ip_ru(const string& ip) {
    GeoInfo g; g.source = "2ip.io (RU)";
    string url = "http://api.2ip.me/geo.json";
    if (!ip.empty()) url += "?ip=" + ip;
    auto r = http_get(url);
    if (!r.ok()) { g.err = "http " + std::to_string(r.status) + " " + r.err; return g; }
    g.ip           = json_get_str(r.body, "ip");
    g.country      = json_get_str(r.body, "country");
    if (g.country.empty()) g.country = json_get_str(r.body, "country_rus");
    g.country_code = json_get_str(r.body, "country_code");
    g.city         = json_get_str(r.body, "city");
    if (g.city.empty()) g.city = json_get_str(r.body, "city_rus");
    return g;
}

// ============================================================================
// Port lists
// ============================================================================
// Curated "fast" port list (205 ports): VPN/proxy/TLS/admin/tor/xray defaults.
// Used when --fast is passed. Default mode is FULL (1-65535).
static const vector<int> TCP_FAST_PORTS = {
    // ssh/mail/web/dns
    21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 179, 389, 443,
    445, 465, 514, 515, 548, 587, 631, 636, 873, 990, 993, 995,
    // proxy / socks
    1080, 1081, 1082, 1090, 1180, 1443, 1701, 1723,
    3128, 3129, 3130, 3389, 3690, 4433, 4443, 4444, 4500,
    // tls/https alt
    5000, 5001, 5060, 5061, 5222, 5223, 5228, 5269, 5280, 5432, 5500,
    5555, 5900, 5938, 6000, 6379, 6443, 6667, 6697, 6881,
    // modern alt-tls/HTTP/admin
    7000, 7001, 7070, 7443, 7547, 7777, 7999,
    8000, 8008, 8009, 8010, 8018, 8020, 8030, 8040, 8060, 8080, 8081, 8082,
    8083, 8088, 8090, 8091, 8096, 8100, 8118, 8123, 8181, 8188, 8200, 8222,
    8333, 8383, 8388, 8389, 8443, 8444, 8445, 8480, 8500, 8800, 8843, 8880,
    8888, 8889, 8899, 8989,
    // xray/v2ray/reality defaults
    9000, 9001, 9002, 9007, 9050, 9051, 9090, 9091, 9100, 9200, 9300, 9418,
    9443, 9999,
    // 10k range
    10000, 10001, 10050, 10080, 10443, 10800, 10808, 10809, 10810, 10811,
    11211, 11443, 12000, 13000, 13306, 13579, 14443, 14444, 14567,
    15000, 16000, 16999, 17000, 17777, 18080, 18443, 19132, 19999,
    20000, 20443, 21443, 22222, 22443, 23443, 24443, 25443,
    27015, 27017, 28017, 30000, 30003, 31337, 32400,
    33389, 35000, 36000, 36363, 37000, 38000, 39000, 40000,
    41641, 41642, 42000, 43210, 44443, 45000, 46443, 48000,
    49152, 50000, 50051, 50443, 51443, 51820, 51821, 52323, 53333,
    54321, 55443, 55554, 56789, 57621, 58080, 59999, 60000, 61613, 62078, 65000
};
// Build port list per selected PortMode.
static vector<int> build_tcp_ports() {
    vector<int> p;
    switch (g_port_mode) {
        case PortMode::FAST:
            p = TCP_FAST_PORTS; break;
        case PortMode::RANGE: {
            int lo = std::max(1,  g_range_lo);
            int hi = std::min(65535, g_range_hi);
            p.reserve(hi-lo+1);
            for (int i=lo; i<=hi; ++i) p.push_back(i);
        } break;
        case PortMode::LIST:
            p = g_port_list; break;
        case PortMode::FULL:
        default:
            p.reserve(65535);
            for (int i=1; i<=65535; ++i) p.push_back(i);
            break;
    }
    return p;
}

static const vector<int> UDP_SCAN_PORTS = {
    53, 67, 69, 80, 123, 137, 138, 161, 443, 500, 514, 520, 554, 623,
    1194, 1434, 1645, 1701, 1812, 1813, 1900, 2049, 2152, 2302, 2427,
    3702, 4433, 4500, 4789, 5060, 5353, 5683, 6881, 10000, 27015, 41641,
    51820
};

// ============================================================================
// Port fingerprints (reference)
// ============================================================================
struct PortHint { int port; const char* svc; const char* proto; };
static const vector<PortHint> PORT_HINTS = {
    {22,"SSH","tcp"},{53,"DNS","tcp/udp"},{80,"HTTP","tcp"},{88,"Kerberos","tcp"},
    {443,"HTTPS / XTLS / Reality","tcp"},{465,"SMTPS","tcp"},{587,"SMTP+TLS","tcp"},
    {853,"DoT","tcp"},{990,"FTPS","tcp"},{993,"IMAPS","tcp"},{995,"POP3S","tcp"},
    {1080,"SOCKS5","tcp"},{1194,"OpenVPN","tcp/udp"},{1701,"L2TP","udp"},
    {1723,"PPTP","tcp"},{3128,"Squid HTTP proxy","tcp"},{3389,"RDP","tcp"},
    {4433,"XTLS/Reality/Trojan","tcp"},{4443,"XTLS/Reality","tcp"},
    {4500,"IKEv2 NAT-T","udp"},{5060,"SIP","tcp/udp"},{5555,"ADB / alt-admin","tcp"},
    {8080,"HTTP proxy","tcp"},{8118,"Privoxy","tcp"},{8123,"Polipo","tcp"},
    {8388,"Shadowsocks","tcp/udp"},{8443,"HTTPS alt / Reality","tcp"},
    {8888,"HTTP alt","tcp"},{9050,"Tor SOCKS","tcp"},{9051,"Tor control","tcp"},
    {10808,"v2ray/xray SOCKS","tcp"},{10809,"v2ray/xray HTTP","tcp"},
    {10810,"v2ray/xray alt","tcp"},
    {51820,"WireGuard","udp"},{41641,"Tailscale","udp"},
    {500,"IKE ISAKMP","udp"},{1194,"OpenVPN","udp"},
};

static const char* port_hint(int p) {
    for (auto& h: PORT_HINTS) if (h.port == p) return h.svc;
    if (p == 6443 || p == 8443 || p == 4443) return "HTTPS alt / possible VPN over TLS";
    if (p >= 10800 && p <= 10820) return "v2ray/xray local-like range";
    return "";
}

// ============================================================================
// TCP port scan (parallel)
// ============================================================================
struct TcpOpen {
    int port;
    long long connect_ms;
    string banner; // grabbed on connect, if any
};

static TcpOpen probe_tcp(const string& host, int port, int to_ms) {
    TcpOpen o; o.port = port; o.connect_ms = -1;
    auto t0 = std::chrono::steady_clock::now();
    string err; SOCKET s = tcp_connect(host, port, to_ms, err);
    if (s == INVALID_SOCKET) return o;
    o.connect_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                     std::chrono::steady_clock::now() - t0).count();
    // passive banner grab (some servers talk first: SSH/FTP/SMTP)
    char buf[512]; int n = tcp_recv_to(s, buf, sizeof(buf)-1, 600);
    if (n > 0) {
        buf[n]=0;
        o.banner.assign(buf, n);
        // strip trailing control
        while (!o.banner.empty() && (o.banner.back()=='\r'||o.banner.back()=='\n'||o.banner.back()==0))
            o.banner.pop_back();
    }
    closesocket(s);
    return o;
}

static vector<TcpOpen> scan_tcp(const string& host, const vector<int>& ports, int threads, int to_ms) {
    vector<TcpOpen> open;
    std::mutex mx;
    std::atomic<size_t> idx{0};
    std::atomic<int>    done{0};
    auto worker = [&]{
        while (true) {
            size_t i = idx.fetch_add(1);
            if (i >= ports.size()) break;
            TcpOpen o = probe_tcp(host, ports[i], to_ms);
            int d = ++done;
            if (o.connect_ms >= 0) {
                std::lock_guard<std::mutex> lk(mx);
                open.push_back(std::move(o));
            }
            if (d % 20 == 0 || (size_t)d == ports.size()) {
                fprintf(stderr, "\r  scanning %d/%zu  open=%zu  ", d, ports.size(), open.size());
                fflush(stderr);
            }
        }
    };
    threads = std::max(1, std::min(threads, (int)ports.size()));
    vector<std::thread> th;
    for (int i=0;i<threads;++i) th.emplace_back(worker);
    for (auto& t: th) t.join();
    fprintf(stderr, "\r  scan done (%zu/%zu, open=%zu)        \n", ports.size(), ports.size(), open.size());
    std::sort(open.begin(), open.end(), [](auto&a,auto&b){return a.port<b.port;});
    return open;
}

// ============================================================================
// Service fingerprints
// ============================================================================
struct FpResult {
    string service;
    string details;      // short info line
    string raw_hex;      // for debugging (optional)
    bool   is_vpn_like = false;
    bool   silent      = false; // didn't respond to probes
};

static string printable_prefix(const string& s, size_t lim = 80) {
    string out;
    for (size_t i=0;i<s.size() && out.size()<lim;++i) {
        char c = s[i];
        if (c>=32 && c<127) out += c;
        else if (c=='\r') out += "\\r";
        else if (c=='\n') out += "\\n";
        else out += '.';
    }
    return out;
}

// HTTP probe (plain)
static FpResult fp_http_plain(const string& host, int port) {
    FpResult f; f.service = "HTTP?";
    string err; SOCKET s = tcp_connect(host, port, g_tcp_to, err);
    if (s == INVALID_SOCKET) { f.silent = true; return f; }
    string req = "GET / HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: Mozilla/5.0\r\nConnection: close\r\n\r\n";
    tcp_send_all(s, req.data(), (int)req.size());
    char buf[2048]; int n = tcp_recv_to(s, buf, sizeof(buf)-1, 1500);
    closesocket(s);
    if (n <= 0) { f.silent = true; return f; }
    buf[n]=0; string resp(buf, n);
    string first = resp.substr(0, resp.find('\n'));
    string server;
    size_t sv = tolower_s(resp).find("server:");
    if (sv != string::npos) {
        size_t e = resp.find('\r', sv);
        if (e == string::npos) e = resp.find('\n', sv);
        server = trim(resp.substr(sv+7, e-(sv+7)));
    }
    f.service = "HTTP";
    f.details = trim(first);
    if (!server.empty()) f.details += "  | Server: " + server;
    // heuristics: does server leak nginx/caddy/trojan/xray fallback?
    string rl = tolower_s(server);
    if (contains(rl, "caddy"))     f.details += "  %[caddy-fronted — common Xray/Reality fallback]";
    else if (contains(rl, "nginx")) f.details += "  %[nginx — fallback host?]";
    else if (contains(rl, "cloudflare")) f.details += "  %[cloudflare]";
    return f;
}

// SSH banner
static FpResult fp_ssh(const string& banner_hint, const string& host, int port) {
    FpResult f; f.service = "SSH?";
    string b = banner_hint;
    if (b.empty() || b.substr(0,4) != "SSH-") {
        // re-grab
        string err; SOCKET s = tcp_connect(host, port, g_tcp_to, err);
        if (s != INVALID_SOCKET) {
            char buf[256]; int n = tcp_recv_to(s, buf, sizeof(buf)-1, 1500);
            closesocket(s);
            if (n > 0) { buf[n]=0; b.assign(buf,n); }
        }
    }
    if (b.substr(0,4) == "SSH-") {
        f.service = "SSH";
        // strip CR/LF
        while (!b.empty() && (b.back()=='\r'||b.back()=='\n')) b.pop_back();
        f.details = b;
    } else {
        f.details = "no SSH banner (but port open)";
    }
    return f;
}

// SOCKS5 probe: send greeting, expect 0x05 reply
static FpResult fp_socks5(const string& host, int port) {
    FpResult f; f.service = "SOCKS?";
    string err; SOCKET s = tcp_connect(host, port, g_tcp_to, err);
    if (s == INVALID_SOCKET) { f.silent = true; return f; }
    unsigned char greet[] = {0x05, 0x02, 0x00, 0x02}; // ver, nmethods=2, NO-AUTH + USER/PASS
    tcp_send_all(s, greet, sizeof(greet));
    unsigned char reply[8]; int n = tcp_recv_to(s, (char*)reply, sizeof(reply), 1200);
    closesocket(s);
    if (n <= 0) { f.silent = true; return f; }
    if (reply[0] == 0x05) {
        f.service = "SOCKS5";
        f.details = "methods=0x" + hex_s(reply+1, std::min(1,n-1));
        if (reply[1] == 0x00) f.details += " (no-auth)";
        else if (reply[1] == 0x02) f.details += " (user/pass)";
        else if (reply[1] == 0xFF) f.details += " (no acceptable)";
        f.is_vpn_like = true;
    } else if (reply[0] == 0x04) {
        f.service = "SOCKS4"; f.is_vpn_like = true;
    } else {
        f.details = "reply=" + hex_s(reply, std::min(4,n));
    }
    return f;
}

// HTTP CONNECT proxy probe
static FpResult fp_http_connect(const string& host, int port) {
    FpResult f; f.service = "HTTP-PROXY?";
    string err; SOCKET s = tcp_connect(host, port, g_tcp_to, err);
    if (s == INVALID_SOCKET) { f.silent = true; return f; }
    string req = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
    tcp_send_all(s, req.data(), (int)req.size());
    char buf[512]; int n = tcp_recv_to(s, buf, sizeof(buf)-1, 1500);
    closesocket(s);
    if (n <= 0) { f.silent = true; return f; }
    buf[n]=0;
    string line(buf, buf + std::min(n, 120));
    if (starts_with(line, "HTTP/")) {
        f.service = "HTTP-PROXY";
        f.details = trim(line.substr(0, line.find('\n')));
        f.is_vpn_like = true;
    } else {
        f.details = printable_prefix(line);
    }
    return f;
}

// Shadowsocks probe: open + send random 32 bytes, expect server to just close (AEAD rejects invalid)
// a common heuristic: connect, send garbage, measure how fast RST comes vs timeout
static FpResult fp_shadowsocks(const string& host, int port) {
    FpResult f; f.service = "SS?";
    string err; SOCKET s = tcp_connect(host, port, g_tcp_to, err);
    if (s == INVALID_SOCKET) { f.silent = true; return f; }
    unsigned char rnd[64];
    for (int i=0;i<64;++i) rnd[i] = (unsigned char)(rand()&0xFF);
    tcp_send_all(s, rnd, 64);
    char buf[256]; int n = tcp_recv_to(s, buf, sizeof(buf), 800);
    closesocket(s);
    if (n <= 0) {
        f.service = "silent-on-junk";
        f.details = "accepts random bytes but never replies (ambiguous: Shadowsocks AEAD, Trojan, Reality hidden-mode, or any firewalled service)";
        // do NOT set is_vpn_like: this pattern is not specific to VPN stacks
    } else {
        f.details = "responded "+std::to_string(n)+"B: "+printable_prefix(string(buf,n));
    }
    return f;
}

// ============================================================================
// TLS module (OpenSSL) — includes JA3-like fingerprint
// ============================================================================
struct TlsProbe {
    bool   ok = false;
    string err;
    string version;
    string cipher;
    string alpn;
    string group;
    string cert_subject;
    string cert_issuer;
    string cert_sha256;
    vector<string> san;
    int64_t handshake_ms = 0;
};

static string x509_name_one(X509_NAME* n) {
    char b[512]={0};
    X509_NAME_oneline(n, b, sizeof(b));
    return b;
}

static TlsProbe tls_probe(const string& ip, int port, const string& sni,
                          const string& alpn = "h2,http/1.1",
                          int to_ms = 5000) {
    TlsProbe r;
    auto t0 = std::chrono::steady_clock::now();
    string err; SOCKET s = tcp_connect(ip, port, to_ms, err);
    if (s == INVALID_SOCKET) { r.err = err; return r; }
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, (int)s);
    if (!sni.empty()) SSL_set_tlsext_host_name(ssl, sni.c_str());
    // ALPN
    vector<unsigned char> wire;
    for (auto& p: split(alpn, ',')) {
        string v = trim(p); if (v.empty()) continue;
        wire.push_back((unsigned char)v.size());
        for (char c: v) wire.push_back((unsigned char)c);
    }
    if (!wire.empty()) SSL_set_alpn_protos(ssl, wire.data(), (unsigned)wire.size());
    if (SSL_connect(ssl) != 1) {
        unsigned long e = ERR_get_error();
        char b[256]; ERR_error_string_n(e, b, sizeof(b));
        r.err = b[0] ? string(b) : string("tls handshake failed");
        SSL_free(ssl); SSL_CTX_free(ctx); closesocket(s);
        return r;
    }
    r.ok = true;
    r.version = SSL_get_version(ssl);
    r.cipher  = SSL_get_cipher_name(ssl);
    const unsigned char* ap=nullptr; unsigned apl=0;
    SSL_get0_alpn_selected(ssl, &ap, &apl);
    if (apl) r.alpn.assign((const char*)ap, apl);
    int nid = SSL_get_negotiated_group(ssl);
    const char* gn = OBJ_nid2sn(nid);
    if (gn) r.group = gn;
    X509* cert = SSL_get_peer_certificate(ssl);
    if (cert) {
        r.cert_subject = x509_name_one(X509_get_subject_name(cert));
        r.cert_issuer  = x509_name_one(X509_get_issuer_name(cert));
        unsigned char dgst[32]; unsigned dl = 0;
        X509_digest(cert, EVP_sha256(), dgst, &dl);
        r.cert_sha256 = hex_s(dgst, dl);
        GENERAL_NAMES* gens = (GENERAL_NAMES*)X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr);
        if (gens) {
            int nn = sk_GENERAL_NAME_num(gens);
            for (int i=0;i<nn;++i) {
                GENERAL_NAME* g = sk_GENERAL_NAME_value(gens, i);
                if (g->type == GEN_DNS) {
                    unsigned char* us = nullptr;
                    int ul = ASN1_STRING_to_UTF8(&us, g->d.dNSName);
                    if (ul > 0) r.san.push_back(string((char*)us, ul));
                    OPENSSL_free(us);
                }
            }
            GENERAL_NAMES_free(gens);
        }
        X509_free(cert);
    }
    SSL_shutdown(ssl);
    SSL_free(ssl); SSL_CTX_free(ctx); closesocket(s);
    r.handshake_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::steady_clock::now() - t0).count();
    return r;
}

// ============================================================================
// SNI consistency test — probe with foreign SNIs, compare cert fingerprints.
//
// Reality discriminator (vs. plain TLS-with-one-cert false-positive):
//   * "same cert returned for every SNI" ALONE is NOT Reality — a plain
//     nginx with a single default cert exhibits the same behavior.
//   * Real Reality proxies the TLS handshake to dest= (typically a major
//     third-party site like www.microsoft.com), so the returned cert is
//     valid for THAT third-party domain, not for the operator's own name.
//   * So: declare reality_like ONLY when (same cert always) AND (the
//     returned cert is valid for at least one of our probed foreign SNIs).
// ============================================================================
struct SniConsistency {
    string base_sni;
    string base_sha;
    string base_subject;
    vector<string> base_san;
    struct Entry { string sni; bool ok; string sha; string subject; };
    vector<Entry> entries;
    bool same_cert_always = false;
    bool reality_like = false;
    bool default_cert_only = false; // plain server with a single default cert
    string matched_foreign_sni;     // which probed SNI the cert actually serves
};

// Case-insensitive DNS-name match with wildcard support ("*.example.com").
static bool dns_name_match(const string& name, const string& pat) {
    if (name.empty() || pat.empty()) return false;
    if (pat.size() > 2 && pat[0] == '*' && pat[1] == '.') {
        string suffix = pat.substr(1); // ".example.com"
        if (name.size() <= suffix.size()) return false;
        size_t off = name.size() - suffix.size();
        return _stricmp(name.c_str() + off, suffix.c_str()) == 0 &&
               name.find('.') == off; // exactly one label in place of "*"
    }
    return _stricmp(name.c_str(), pat.c_str()) == 0;
}

static string extract_cn(const string& subject_oneline) {
    // Format: /C=US/O=Microsoft Corporation/CN=www.microsoft.com
    size_t pos = subject_oneline.find("/CN=");
    if (pos == string::npos) return "";
    size_t end = subject_oneline.find('/', pos + 4);
    return subject_oneline.substr(pos + 4,
        end == string::npos ? string::npos : end - pos - 4);
}

static bool cert_covers_name(const string& sni,
                             const string& subject_oneline,
                             const vector<string>& san) {
    string cn = extract_cn(subject_oneline);
    if (dns_name_match(sni, cn)) return true;
    for (auto& s: san) if (dns_name_match(sni, s)) return true;
    return false;
}

static SniConsistency sni_consistency(const string& ip, int port, const string& base_sni) {
    SniConsistency c; c.base_sni = base_sni;
    TlsProbe base = tls_probe(ip, port, base_sni);
    if (!base.ok) return c;
    c.base_sha     = base.cert_sha256;
    c.base_subject = base.cert_subject;
    c.base_san     = base.san;
    static const vector<string> alt = {
        "www.microsoft.com", "www.apple.com", "addons.mozilla.org",
        "random-domain-that-does-not-exist.example", "www.yandex.ru"
    };
    int same = 0, total = 0;
    for (auto& s: alt) {
        TlsProbe p = tls_probe(ip, port, s);
        SniConsistency::Entry e;
        e.sni = s;
        e.ok  = p.ok;
        e.sha = p.cert_sha256;
        e.subject = p.cert_subject;
        if (p.ok) {
            ++total;
            if (p.cert_sha256 == base.cert_sha256) ++same;
        }
        c.entries.push_back(std::move(e));
    }
    if (total >= 3 && same == total) {
        c.same_cert_always = true;
        // Reality discriminator:
        //   * Real Reality proxies to dest= (e.g. microsoft.com), so the
        //     returned cert is valid for dest=, but NOT for the operator's
        //     own hostname (base_sni). The operator owns "reality.example"
        //     but the TLS cert shown to us is for "www.microsoft.com".
        //   * A plain server (e.g. the actual microsoft.com) returns a
        //     cert that covers its own hostname = base_sni. That is the
        //     normal case — NOT Reality.
        //   * A plain server with a mismatched default cert (e.g. nginx
        //     showing a self-signed cert regardless of SNI) returns a cert
        //     that covers neither base_sni nor any foreign probe SNI.
        bool cert_covers_base = cert_covers_name(base_sni, base.cert_subject, base.san);
        if (!cert_covers_base) {
            for (auto& s: alt) {
                if (_stricmp(s.c_str(), base_sni.c_str()) == 0) continue;
                if (cert_covers_name(s, base.cert_subject, base.san)) {
                    c.reality_like = true;
                    c.matched_foreign_sni = s;
                    break;
                }
            }
        }
        if (!c.reality_like) c.default_cert_only = true;
    }
    return c;
}

// ============================================================================
// J3 / TSPU / GFW-style active probing
// ============================================================================
struct J3Result {
    string name;
    bool   responded = false;
    int    bytes = 0;
    string first_line;
    string hex_head;
    int64_t ms = 0;
};

static J3Result j3_send(const string& host, int port, const string& name,
                        const void* data, int dlen, bool close_after_send=false) {
    J3Result r; r.name = name;
    auto t0 = std::chrono::steady_clock::now();
    string err; SOCKET s = tcp_connect(host, port, g_tcp_to, err);
    if (s == INVALID_SOCKET) return r;
    if (dlen > 0) tcp_send_all(s, data, dlen);
    if (close_after_send) { closesocket(s); return r; }
    char buf[1024]; int n = tcp_recv_to(s, buf, sizeof(buf)-1, 1200);
    closesocket(s);
    r.ms = std::chrono::duration_cast<std::chrono::milliseconds>(
             std::chrono::steady_clock::now() - t0).count();
    if (n > 0) {
        r.responded = true; r.bytes = n;
        string raw(buf, n);
        size_t nl = raw.find('\n');
        r.first_line = trim(raw.substr(0, nl == string::npos ? raw.size() : nl));
        r.hex_head = hex_s((unsigned char*)buf, std::min(16, n), true);
    }
    return r;
}

static vector<J3Result> j3_probes(const string& host, int port) {
    vector<J3Result> out;
    // 1) Empty payload — just close after connect
    {
        string err; SOCKET s = tcp_connect(host, port, g_tcp_to, err);
        J3Result r; r.name = "empty/close";
        if (s != INVALID_SOCKET) {
            char buf[128]; int n = tcp_recv_to(s, buf, sizeof(buf)-1, 800);
            if (n > 0) { r.responded = true; r.bytes = n; r.first_line = printable_prefix(string(buf,n)); r.hex_head = hex_s((unsigned char*)buf, std::min(16,n), true); }
            closesocket(s);
        }
        out.push_back(r);
    }
    // 2) HTTP GET /
    {
        string req = "GET / HTTP/1.1\r\nHost: x\r\nUser-Agent: curl/8\r\n\r\n";
        out.push_back(j3_send(host, port, "HTTP GET /", req.data(), (int)req.size()));
    }
    // 3) CONNECT proxy-style
    {
        string req = "CONNECT 1.2.3.4:443 HTTP/1.1\r\nHost: 1.2.3.4\r\n\r\n";
        out.push_back(j3_send(host, port, "HTTP CONNECT", req.data(), (int)req.size()));
    }
    // 4) SSH banner (server-in-client-role)
    {
        string req = "SSH-2.0-ByeByeVPN\r\n";
        out.push_back(j3_send(host, port, "SSH banner", req.data(), (int)req.size()));
    }
    // 5) 512 random bytes
    {
        unsigned char buf[512]; for (int i=0;i<512;++i) buf[i]=(unsigned char)(rand()&0xFF);
        out.push_back(j3_send(host, port, "random 512B", buf, 512));
    }
    // 6) TLS ClientHello minimal (TLS1.0 wrapping, random SNI)
    {
        // handcrafted minimal TLS 1.0 ClientHello with a random SNI "foo.invalid"
        static const unsigned char hello[] = {
            0x16,0x03,0x01,0x00,0x70,     // TLS record: handshake, 0x70 len
            0x01,0x00,0x00,0x6c,          // handshake: client_hello, len 0x6c
            0x03,0x03,                    // TLS 1.2
            // 32 bytes random
            0x52,0x55,0x53,0x53,0x49,0x41,0x4e,0x00,
            0x42,0x59,0x45,0x42,0x59,0x45,0x56,0x50,
            0x4e,0x41,0x43,0x54,0x49,0x56,0x45,0x50,
            0x52,0x4f,0x42,0x45,0x4a,0x33,0x00,0x00,
            0x00,                         // session id len
            0x00,0x02,                    // cipher suites len
            0x13,0x02,                    // TLS_AES_256_GCM_SHA384
            0x01,0x00,                    // compression: null
            // extensions
            0x00,0x41,
            0x00,0x00,0x00,0x10, 0x00,0x0e, 0x00,0x00,0x0b,'f','o','o','.','i','n','v','a','l','i','d',
            0x00,0x10,0x00,0x0b, 0x00,0x09, 0x08,'h','t','t','p','/','1','.','1',
            0x00,0x0b,0x00,0x02, 0x01,0x00,
            0x00,0x0a,0x00,0x04, 0x00,0x02,0x00,0x1d,
            0x00,0x0d,0x00,0x0a, 0x00,0x08, 0x04,0x01, 0x05,0x01, 0x08,0x07, 0x08,0x08,
            0x00,0x2b,0x00,0x03, 0x02,0x03,0x04,
            0x00,0x33,0x00,0x02, 0x00,0x00
        };
        out.push_back(j3_send(host, port, "TLS CH invalid-SNI", hello, (int)sizeof(hello)));
    }
    // 7) HTTP/1.0 proxy request with absolute URL
    {
        string req = "GET http://example.com/ HTTP/1.1\r\nHost: example.com\r\n\r\n";
        out.push_back(j3_send(host, port, "HTTP abs-URI (proxy-style)", req.data(), (int)req.size()));
    }
    // 8) trash first byte 0xFF x 128 then TLS
    {
        unsigned char garb[128]; memset(garb, 0xFF, sizeof(garb));
        out.push_back(j3_send(host, port, "0xFF x128", garb, sizeof(garb)));
    }
    return out;
}

// ============================================================================
// QUIC (HTTP/3) initial probe on UDP/443
// ============================================================================
static UdpResult quic_probe(const string& host, int port) {
    // Minimal QUIC v1 Initial with CRYPTO frame (bogus but valid length) → should trigger Version Negotiation or retry
    static const unsigned char pkt[] = {
        0xc0,                        // long header, type Initial
        0x00,0x00,0x00,0x01,         // QUIC version 1
        0x08,                        // DCID len
        0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB,0xBB, // DCID
        0x00,                        // SCID len
        0x00,                        // Token len
        0x44,0x40,                   // Length varint (1088)
        // payload (not real encryption — server should ignore / NEG)
    };
    vector<unsigned char> full(1200, 0x00);
    memcpy(full.data(), pkt, sizeof(pkt));
    return udp_probe(host, port, full.data(), (int)full.size(), 1500);
}

// ============================================================================
// OpenVPN UDP probe: HARD_RESET_CLIENT_V2
// ============================================================================
static UdpResult openvpn_probe(const string& host, int port) {
    unsigned char pkt[26];
    pkt[0] = 0x38; // P_CONTROL_HARD_RESET_CLIENT_V2 (7) << 3 | key_id 0 = 0x38
    RAND_bytes(pkt+1, 8);     // session id
    pkt[9] = 0x00;            // packet id array len
    unsigned int pid = htonl(0);
    memcpy(pkt+10, &pid, 4);  // packet id
    unsigned int ts = htonl((unsigned int)time(nullptr));
    memcpy(pkt+14, &ts, 4);   // timestamp
    RAND_bytes(pkt+18, 8);    // some padding
    return udp_probe(host, port, pkt, sizeof(pkt), 1200);
}

// ============================================================================
// WireGuard UDP probe: MessageInitiation (148B)
// ============================================================================
static UdpResult wireguard_probe(const string& host, int port) {
    unsigned char pkt[148] = {0};
    pkt[0] = 0x01;   // type: handshake initiation
    RAND_bytes(pkt+4, 140); // rest: sender idx + ephemeral + encrypted static + encrypted timestamp + mac1/mac2
    return udp_probe(host, port, pkt, sizeof(pkt), 1500);
}

// ============================================================================
// IKE ISAKMP probe (UDP/500): 28-byte header, nothing meaningful
// ============================================================================
static UdpResult ike_probe(const string& host, int port) {
    unsigned char pkt[28] = {0};
    RAND_bytes(pkt, 8);       // ICOOKIE
    // RCOOKIE all-zero (initiator)
    pkt[16] = 0x21;           // next payload: SA (1) + version hint
    pkt[17] = 0x20;           // IKEv2 version 2.0
    pkt[18] = 0x22;           // exchange type: IKE_SA_INIT (34)
    pkt[19] = 0x08;           // flags: Initiator
    // message id = 0
    // length = 28
    pkt[24] = 0; pkt[25] = 0; pkt[26] = 0; pkt[27] = 28;
    return udp_probe(host, port, pkt, sizeof(pkt), 1200);
}

// ============================================================================
// DNS UDP/53 probe — A query for example.com
// ============================================================================
static UdpResult dns_probe(const string& host, int port) {
    // txn id 0xBEEF, flags standard query, 1 question: example.com A
    static const unsigned char q[] = {
        0xBE,0xEF, 0x01,0x00, 0x00,0x01, 0x00,0x00, 0x00,0x00, 0x00,0x00,
        0x07,'e','x','a','m','p','l','e', 0x03,'c','o','m', 0x00,
        0x00,0x01, 0x00,0x01
    };
    return udp_probe(host, port, q, sizeof(q), 1200);
}

// ============================================================================
// Local analysis (this machine): adapters, routes, VPN processes, configs
// ============================================================================
struct LocalAdapter {
    string  friendly;       // "Ethernet 3"
    string  description;    // "WireGuard Tunnel"
    string  mac;
    vector<string> ipv4;
    vector<string> ipv6;
    vector<string> gateways;
    unsigned long mtu = 0;
    unsigned long if_index = 0;
    bool    is_vpn = false; // TAP/TUN/WG/WARP/etc
    bool    is_up  = false;
};

struct LocalRoute {
    string prefix;          // "0.0.0.0/0"
    string nexthop;         // "192.168.1.1"
    unsigned long if_index = 0;
    unsigned long metric   = 0;
    string via_adapter;     // filled later
    bool   via_vpn = false;
};

struct LocalProcess {
    unsigned long pid = 0;
    string name;
    string exe_path;
    string category;        // "xray", "wireguard", "warp", ...
};

static bool icontains(const string& hay, const char* needle) {
    string a = hay, b = needle;
    std::transform(a.begin(), a.end(), a.begin(), ::tolower);
    std::transform(b.begin(), b.end(), b.begin(), ::tolower);
    return a.find(b) != string::npos;
}

static string mac_to_str(const unsigned char* mac, int len) {
    char buf[64]; buf[0]=0;
    for (int i=0;i<len;++i)
        sprintf(buf+strlen(buf), "%02X%s", mac[i], i<len-1?":":"");
    return buf;
}

static string sockaddr_to_str(SOCKADDR* sa) {
    char buf[INET6_ADDRSTRLEN] = {0};
    if (sa->sa_family == AF_INET) {
        sockaddr_in* s = (sockaddr_in*)sa;
        inet_ntop(AF_INET, &s->sin_addr, buf, sizeof(buf));
    } else if (sa->sa_family == AF_INET6) {
        sockaddr_in6* s = (sockaddr_in6*)sa;
        inet_ntop(AF_INET6, &s->sin6_addr, buf, sizeof(buf));
    }
    return buf;
}

// Keywords that identify VPN-like adapters by description/name.
static bool adapter_is_vpn(const string& desc, const string& name) {
    static const char* kw[] = {
        "TAP-Windows", "TAP-ProtonVPN", "WireGuard", "WireGuard Tunnel",
        "Wintun", "TUN", "Tun ", "OpenVPN", "Mullvad", "NordLynx", "ProtonVPN",
        "Cloudflare WARP", "Hiddify", "Amnezia", "singbox", "sing-box",
        "v2ray", "xray", "AmneziaWG", "ExpressVPN", "Private Internet",
        "PIA", "Surfshark", "TorGuard"
    };
    for (auto k: kw) if (icontains(desc, k) || icontains(name, k)) return true;
    return false;
}

static vector<LocalAdapter> list_local_adapters() {
    vector<LocalAdapter> out;
    ULONG sz = 0;
    GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                         nullptr, nullptr, &sz);
    if (!sz) return out;
    vector<unsigned char> buf(sz);
    auto* aa = (IP_ADAPTER_ADDRESSES*)buf.data();
    if (GetAdaptersAddresses(AF_UNSPEC, GAA_FLAG_INCLUDE_GATEWAYS | GAA_FLAG_SKIP_ANYCAST | GAA_FLAG_SKIP_MULTICAST,
                             nullptr, aa, &sz) != NO_ERROR) return out;
    for (auto* p = aa; p; p = p->Next) {
        LocalAdapter A;
        char fn[256] = {0};
        WideCharToMultiByte(CP_UTF8, 0, p->FriendlyName, -1, fn, sizeof(fn), nullptr, nullptr);
        A.friendly = fn;
        char dc[256] = {0};
        WideCharToMultiByte(CP_UTF8, 0, p->Description, -1, dc, sizeof(dc), nullptr, nullptr);
        A.description = dc;
        if (p->PhysicalAddressLength)
            A.mac = mac_to_str(p->PhysicalAddress, p->PhysicalAddressLength);
        A.mtu = p->Mtu;
        A.if_index = p->IfIndex;
        A.is_up = (p->OperStatus == IfOperStatusUp);
        for (auto* u = p->FirstUnicastAddress; u; u = u->Next) {
            string s = sockaddr_to_str(u->Address.lpSockaddr);
            if (s.empty()) continue;
            if (u->Address.lpSockaddr->sa_family == AF_INET)  A.ipv4.push_back(s);
            else                                              A.ipv6.push_back(s);
        }
        for (auto* g = p->FirstGatewayAddress; g; g = g->Next) {
            string s = sockaddr_to_str(g->Address.lpSockaddr);
            if (!s.empty()) A.gateways.push_back(s);
        }
        A.is_vpn = adapter_is_vpn(A.description, A.friendly);
        out.push_back(std::move(A));
    }
    return out;
}

static vector<LocalRoute> list_local_routes() {
    vector<LocalRoute> out;
    MIB_IPFORWARD_TABLE2* tbl = nullptr;
    if (GetIpForwardTable2(AF_UNSPEC, &tbl) != NO_ERROR || !tbl) return out;
    for (ULONG i=0; i<tbl->NumEntries; ++i) {
        auto& r = tbl->Table[i];
        LocalRoute R;
        char dst[INET6_ADDRSTRLEN]={0}, nh[INET6_ADDRSTRLEN]={0};
        if (r.DestinationPrefix.Prefix.si_family == AF_INET) {
            inet_ntop(AF_INET, &r.DestinationPrefix.Prefix.Ipv4.sin_addr, dst, sizeof(dst));
            inet_ntop(AF_INET, &r.NextHop.Ipv4.sin_addr,                    nh,  sizeof(nh));
        } else if (r.DestinationPrefix.Prefix.si_family == AF_INET6) {
            inet_ntop(AF_INET6, &r.DestinationPrefix.Prefix.Ipv6.sin6_addr, dst, sizeof(dst));
            inet_ntop(AF_INET6, &r.NextHop.Ipv6.sin6_addr,                   nh,  sizeof(nh));
        } else continue;
        R.prefix   = string(dst) + "/" + std::to_string(r.DestinationPrefix.PrefixLength);
        R.nexthop  = nh;
        R.if_index = r.InterfaceIndex;
        R.metric   = r.Metric;
        out.push_back(R);
    }
    FreeMibTable(tbl);
    return out;
}

struct KnownProc { const char* exe; const char* category; };
static const vector<KnownProc> VPN_PROCESSES = {
    {"xray.exe",          "Xray-core"},
    {"v2ray.exe",         "V2Ray"},
    {"sing-box.exe",      "sing-box"},
    {"singbox.exe",       "sing-box"},
    {"v2rayN.exe",        "v2rayN (GUI → Xray)"},
    {"v2rayNG.exe",       "v2rayNG"},
    {"nekoray.exe",       "NekoRay (GUI → sing-box/Xray)"},
    {"nekobox.exe",       "NekoBox"},
    {"Hiddify.exe",       "Hiddify"},
    {"HiddifyCli.exe",    "Hiddify CLI"},
    {"HiddifyTray.exe",   "Hiddify tray"},
    {"wg.exe",            "WireGuard CLI"},
    {"WireGuard.exe",     "WireGuard (Windows client)"},
    {"wireguard.exe",     "WireGuard"},
    {"tunnel.exe",        "WireGuard tunnel service"},
    {"tun2socks.exe",     "tun2socks"},
    {"openvpn.exe",       "OpenVPN"},
    {"openvpn-gui.exe",   "OpenVPN GUI"},
    {"warp-svc.exe",      "Cloudflare WARP service"},
    {"Cloudflare WARP.exe","Cloudflare WARP"},
    {"ProtonVPN.exe",     "ProtonVPN"},
    {"NordVPN.exe",       "NordVPN"},
    {"ExpressVPN.exe",    "ExpressVPN"},
    {"Mullvad VPN.exe",   "Mullvad"},
    {"Shadowsocks.exe",   "Shadowsocks"},
    {"ShadowsocksR.exe",  "ShadowsocksR"},
    {"clash.exe",         "Clash"},
    {"clash-verge.exe",   "Clash Verge"},
    {"ClashForWindows.exe","Clash for Windows"},
    {"AmneziaVPN.exe",    "AmneziaVPN"},
    {"amneziawg.exe",     "AmneziaWG"},
    {"cisco-vpn.exe",     "Cisco AnyConnect"},
    {"vpncli.exe",        "Cisco AnyConnect CLI"},
};

static vector<LocalProcess> list_vpn_processes() {
    vector<LocalProcess> out;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return out;
    PROCESSENTRY32W pe; pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            char name[260] = {0};
            WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, name, sizeof(name), nullptr, nullptr);
            for (auto& kp: VPN_PROCESSES) {
                if (_stricmp(name, kp.exe) == 0) {
                    LocalProcess LP;
                    LP.pid = pe.th32ProcessID;
                    LP.name = name;
                    LP.category = kp.category;
                    // try to resolve exe path
                    HANDLE h = OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, pe.th32ProcessID);
                    if (h) {
                        wchar_t path[MAX_PATH] = {0};
                        DWORD sz = MAX_PATH;
                        if (QueryFullProcessImageNameW(h, 0, path, &sz)) {
                            char p[MAX_PATH] = {0};
                            WideCharToMultiByte(CP_UTF8, 0, path, -1, p, sizeof(p), nullptr, nullptr);
                            LP.exe_path = p;
                        }
                        CloseHandle(h);
                    }
                    out.push_back(std::move(LP));
                    break;
                }
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return out;
}

struct KnownConfig { const char* envvar; const char* subpath; const char* tool; };
static const vector<KnownConfig> KNOWN_CONFIGS = {
    {"APPDATA",      "\\Xray",                            "Xray-core configs"},
    {"APPDATA",      "\\v2rayN",                          "v2rayN configs"},
    {"APPDATA",      "\\v2ray",                           "V2Ray configs"},
    {"APPDATA",      "\\sing-box",                        "sing-box configs"},
    {"APPDATA",      "\\NekoRay",                         "NekoRay configs"},
    {"APPDATA",      "\\nekobox",                         "NekoBox configs"},
    {"APPDATA",      "\\Hiddify",                         "Hiddify configs"},
    {"APPDATA",      "\\Hiddify Next",                    "Hiddify Next"},
    {"APPDATA",      "\\clash",                           "Clash configs"},
    {"APPDATA",      "\\clash-verge",                     "Clash Verge configs"},
    {"LOCALAPPDATA", "\\WireGuard",                       "WireGuard configs"},
    {"LOCALAPPDATA", "\\Programs\\Amnezia",               "AmneziaVPN client"},
    {"LOCALAPPDATA", "\\Programs\\Hiddify",               "Hiddify install"},
    {"PROGRAMFILES", "\\OpenVPN",                         "OpenVPN install"},
    {"PROGRAMFILES", "\\Cloudflare\\Cloudflare WARP",     "Cloudflare WARP"},
    {"PROGRAMFILES", "\\WireGuard",                       "WireGuard (system)"},
    {"PROGRAMFILES", "\\Mullvad VPN",                     "Mullvad"},
    {"PROGRAMFILES", "\\NordVPN",                         "NordVPN"},
    {"PROGRAMFILES", "\\Proton\\VPN",                     "ProtonVPN"},
};

struct ConfigHit { string tool; string path; };

static vector<ConfigHit> find_known_configs() {
    vector<ConfigHit> out;
    for (auto& k: KNOWN_CONFIGS) {
        char ev[512] = {0}; size_t sz = sizeof(ev);
        if (getenv_s(&sz, ev, sizeof(ev), k.envvar) != 0 || !sz) continue;
        string full = string(ev) + k.subpath;
        DWORD attr = GetFileAttributesA(full.c_str());
        if (attr != INVALID_FILE_ATTRIBUTES)
            out.push_back({k.tool, full});
    }
    return out;
}

static void run_local_analysis() {
    printf("\n%s[LOCAL ANALYSIS] This machine — adapters, routes, VPN software%s\n\n",
           col(C::BOLD), col(C::RST));

    // 1. Adapters
    auto adapters = list_local_adapters();
    printf("%s[1/4] Network adapters%s\n", col(C::BOLD), col(C::RST));
    int vpn_up = 0, phys_up = 0;
    for (auto& A: adapters) {
        if (!A.is_up) continue;
        if (A.is_vpn) ++vpn_up; else if (!A.ipv4.empty()) ++phys_up;
        const char* tag = A.is_vpn ? "[VPN]" : "     ";
        const char* clr = A.is_vpn ? C::YEL : C::DIM;
        printf("  %s%s%s  %s%s%s  ifidx=%lu  mtu=%lu\n",
               col(clr), tag, col(C::RST),
               col(C::BOLD), A.friendly.c_str(), col(C::RST),
               A.if_index, A.mtu);
        printf("         desc: %s\n", A.description.c_str());
        if (!A.mac.empty()) printf("         mac:  %s\n", A.mac.c_str());
        for (auto& ip: A.ipv4) printf("         ipv4: %s\n", ip.c_str());
        for (auto& ip: A.ipv6) printf("         ipv6: %s\n", ip.c_str());
        for (auto& g:  A.gateways) printf("         gw:   %s\n", g.c_str());
    }
    if (vpn_up == 0) printf("  %sno active VPN adapters%s\n", col(C::DIM), col(C::RST));

    // 2. Routes — resolve which interface each route belongs to
    auto routes = list_local_routes();
    std::map<unsigned long, LocalAdapter*> by_idx;
    for (auto& A: adapters) by_idx[A.if_index] = &A;
    for (auto& R: routes) {
        auto it = by_idx.find(R.if_index);
        if (it != by_idx.end()) { R.via_adapter = it->second->friendly; R.via_vpn = it->second->is_vpn; }
    }

    // Find default routes
    printf("\n%s[2/4] Default routes%s\n", col(C::BOLD), col(C::RST));
    vector<LocalRoute*> defaults_v4, defaults_v6;
    for (auto& R: routes) {
        if (R.prefix == "0.0.0.0/0") defaults_v4.push_back(&R);
        if (R.prefix == "::/0")       defaults_v6.push_back(&R);
    }
    std::sort(defaults_v4.begin(), defaults_v4.end(),
              [](auto* a, auto* b){return a->metric < b->metric;});
    for (auto* R: defaults_v4) {
        const char* c = R->via_vpn ? C::YEL : C::CYN;
        printf("  %s0.0.0.0/0%s → %s  via %s%s%s%s  metric=%lu\n",
               col(c), col(C::RST), R->nexthop.c_str(),
               col(C::BOLD),
               R->via_adapter.empty()?"?":R->via_adapter.c_str(),
               R->via_vpn?" [VPN]":"",
               col(C::RST), R->metric);
    }
    if (defaults_v4.empty()) printf("  %sno IPv4 default route%s\n", col(C::RED), col(C::RST));

    // Split-tunnel heuristic
    printf("\n%s[3/4] Tunneling mode%s\n", col(C::BOLD), col(C::RST));
    bool has_vpn_if   = vpn_up > 0;
    bool default_via_vpn = !defaults_v4.empty() && defaults_v4.front()->via_vpn;
    bool has_vpn_specific_route = false;
    for (auto& R: routes) {
        if (R.via_vpn && R.prefix != "0.0.0.0/0" && R.prefix != "::/0"
            && R.prefix.find("/32") == string::npos && R.prefix.find("/128") == string::npos)
            has_vpn_specific_route = true;
    }
    if (!has_vpn_if) {
        printf("  %s⚠ No VPN adapter active — you're on raw ISP connection%s\n",
               col(C::YEL), col(C::RST));
    } else if (default_via_vpn && !has_vpn_specific_route) {
        printf("  %s✓ FULL-TUNNEL%s — all traffic routed through VPN adapter \"%s\"\n",
               col(C::GRN), col(C::RST), defaults_v4.front()->via_adapter.c_str());
    } else if (default_via_vpn && has_vpn_specific_route) {
        printf("  %s↯ FULL-TUNNEL + extra VPN-specific routes%s (likely VPN provider pushed split rules)\n",
               col(C::GRN), col(C::RST));
    } else if (!default_via_vpn && has_vpn_specific_route) {
        printf("  %s✂ SPLIT-TUNNEL%s — default route goes via ISP, but selected subnets go through VPN:\n",
               col(C::MAG), col(C::RST));
        int shown = 0;
        for (auto& R: routes) {
            if (R.via_vpn && R.prefix != "0.0.0.0/0" && R.prefix.find("/32") == string::npos) {
                printf("         %s  →  %s%s%s\n",
                       R.prefix.c_str(), col(C::BOLD), R.via_adapter.c_str(), col(C::RST));
                if (++shown >= 8) { printf("         ... (more omitted)\n"); break; }
            }
        }
    } else {
        printf("  %s? Mixed state%s — VPN adapter up, but default route NOT via VPN\n",
               col(C::YEL), col(C::RST));
    }

    // 3. VPN processes
    printf("\n%s[4/4] VPN software detected (running processes + installed configs)%s\n",
           col(C::BOLD), col(C::RST));
    auto procs = list_vpn_processes();
    if (procs.empty()) printf("  %sno known VPN/proxy processes running%s\n", col(C::DIM), col(C::RST));
    else {
        for (auto& p: procs) {
            printf("  %s● %s%s  pid=%lu  (%s)\n",
                   col(C::GRN), p.name.c_str(), col(C::RST),
                   p.pid, p.category.c_str());
            if (!p.exe_path.empty()) printf("     path: %s\n", p.exe_path.c_str());
        }
    }

    auto cfgs = find_known_configs();
    if (!cfgs.empty()) {
        printf("\n  %sInstalled tools / config dirs:%s\n", col(C::BOLD), col(C::RST));
        for (auto& c: cfgs)
            printf("    %s%-32s%s  %s\n", col(C::CYN), c.tool.c_str(), col(C::RST), c.path.c_str());
    }

    // Summary
    printf("\n%sSummary:%s\n", col(C::BOLD), col(C::RST));
    if (has_vpn_if && default_via_vpn)
        printf("  %s→ You are currently tunneled through VPN.%s\n", col(C::GRN), col(C::RST));
    else if (has_vpn_if && !default_via_vpn && has_vpn_specific_route)
        printf("  %s→ Partial tunnel (split-tunneling active).%s\n", col(C::MAG), col(C::RST));
    else if (has_vpn_if)
        printf("  %s→ VPN adapter exists but traffic NOT through it (disconnected or misrouted).%s\n",
               col(C::YEL), col(C::RST));
    else
        printf("  %s→ No VPN active. Traffic goes directly via your ISP.%s\n",
               col(C::YEL), col(C::RST));
    if (!procs.empty()) {
        set<string> cats;
        for (auto& p: procs) cats.insert(p.category);
        printf("     Software stack running: ");
        int n=0; for (auto& c: cats) printf("%s%s", n++?", ":"", c.c_str()); printf("\n");
    }
}

// ============================================================================
// Verdict engine
// ============================================================================
struct Advice {
    string  kind;    // "risk" or "good" or "note"
    string  text;
};

struct FullReport {
    string target;
    Resolved dns;
    vector<GeoInfo> geos;
    vector<TcpOpen> open_tcp;
    vector<std::pair<int,UdpResult>> udp_probes;
    // fingerprints
    struct PortFp { int port; FpResult fp; optional<TlsProbe> tls; optional<SniConsistency> sni; vector<J3Result> j3; };
    vector<PortFp> fps;
    UdpResult quic;
    // verdict
    int    score = 0;
    string label;
    vector<Advice> advices;
    vector<string> guess_stack;  // "Xray/Reality", "OpenVPN", ...
};

// ============================================================================
// Target pretty print
// ============================================================================
static void print_banner_scan(const string& t) {
    printf("%s%s== Target: %s ==%s\n", col(C::BOLD), col(C::WHT), t.c_str(), col(C::RST));
}

static void print_geo(const GeoInfo& g) {
    if (!g.err.empty()) {
        printf("  %s%-12s%s %serr: %s%s\n",
               col(C::CYN), g.source.c_str(), col(C::RST),
               col(C::RED), g.err.c_str(), col(C::RST));
        return;
    }
    printf("  %s%-12s%s IP %s%-15s%s  %s%s%s  (%s) AS %s %s\n",
           col(C::CYN), g.source.c_str(), col(C::RST),
           col(C::WHT), g.ip.c_str(), col(C::RST),
           col(C::BOLD), g.country_code.empty() ? g.country.c_str() : g.country_code.c_str(), col(C::RST),
           g.city.c_str(), g.asn.c_str(), g.asn_org.c_str());
    string flags;
    auto add = [&](bool v, const char* n, const char* c){
        if (v) { if(!flags.empty()) flags += " "; flags += col(c); flags += n; flags += col(C::RST); }
    };
    add(g.is_hosting, "HOSTING", C::YEL);
    add(g.is_vpn,     "VPN",     C::RED);
    add(g.is_proxy,   "PROXY",   C::RED);
    add(g.is_tor,     "TOR",     C::RED);
    add(g.is_abuser,  "ABUSER",  C::RED);
    if (!flags.empty()) printf("               flags: %s\n", flags.c_str());
}

// ============================================================================
// Orchestrator
// ============================================================================
static FullReport run_full_target(const string& target) {
    FullReport R; R.target = target;

    // 1) resolve
    printf("\n%s[1/7] DNS resolve%s\n", col(C::BOLD), col(C::RST));
    R.dns = resolve_host(target);
    if (!R.dns.err.empty()) {
        printf("  %sERR%s: %s\n", col(C::RED), col(C::RST), R.dns.err.c_str());
        return R;
    }
    printf("  %s%s%s  ->  ", col(C::WHT), target.c_str(), col(C::RST));
    for (auto& ip: R.dns.ips) printf("%s ", ip.c_str());
    printf(" [%s, %lldms]\n", R.dns.family.c_str(), R.dns.ms);

    // 2) GeoIP — 6 sources in parallel (EU/global + RU)
    printf("\n%s[2/7] GeoIP%s  (6 providers in parallel)\n", col(C::BOLD), col(C::RST));
    auto fg1 = std::async(std::launch::async, geo_ipapi_is,   R.dns.primary_ip);
    auto fg2 = std::async(std::launch::async, geo_iplocate,   R.dns.primary_ip);
    auto fg3 = std::async(std::launch::async, geo_ip_api_com, R.dns.primary_ip);
    auto fg4 = std::async(std::launch::async, geo_ipwho_is,   R.dns.primary_ip);
    auto fg5 = std::async(std::launch::async, geo_ipinfo_io,  R.dns.primary_ip);
    auto fg6 = std::async(std::launch::async, geo_freeipapi,  R.dns.primary_ip);
    auto fg7 = std::async(std::launch::async, geo_2ip_ru,     R.dns.primary_ip);
    R.geos.push_back(fg1.get()); R.geos.push_back(fg2.get());
    R.geos.push_back(fg3.get()); R.geos.push_back(fg4.get());
    R.geos.push_back(fg5.get()); R.geos.push_back(fg6.get());
    R.geos.push_back(fg7.get());
    for (auto& g: R.geos) print_geo(g);

    // 3) TCP scan
    auto _ports = build_tcp_ports();
    const char* _mode_name =
        g_port_mode==PortMode::FULL  ? "FULL 1-65535" :
        g_port_mode==PortMode::FAST  ? "FAST (205 curated)" :
        g_port_mode==PortMode::RANGE ? "RANGE" : "LIST";
    printf("\n%s[3/7] TCP port scan%s  mode=%s%s%s  (%zu ports, %d threads, %dms timeout)\n",
           col(C::BOLD), col(C::RST),
           col(C::CYN), _mode_name, col(C::RST),
           _ports.size(), g_threads, g_tcp_to);
    R.open_tcp = scan_tcp(R.dns.primary_ip, _ports, g_threads, g_tcp_to);
    // bogus-open detection: WARP/CGNAT/proxy often ACK every port with same latency
    bool warp_like = false;
    if (R.open_tcp.size() > 60) {
        // sample variance of connect_ms
        long long mn = LLONG_MAX, mx = 0;
        for (auto& o: R.open_tcp) { mn = std::min(mn, o.connect_ms); mx = std::max(mx, o.connect_ms); }
        if (mx - mn < 80) warp_like = true;
    }
    if (warp_like) {
        printf("  %s!! %zu ports reported open with near-identical RTT — looks like Cloudflare WARP / a local proxy / CGNAT middlebox that accept-hooks every TCP SYN. Disable WARP/proxy and re-run; otherwise results are fake%s\n",
               col(C::RED), R.open_tcp.size(), col(C::RST));
    }
    if (R.open_tcp.empty()) {
        printf("  %sno open TCP ports found%s\n", col(C::YEL), col(C::RST));
    } else {
        for (auto& o: R.open_tcp) {
            const char* hint = port_hint(o.port);
            printf("  %s:%-5d%s  %3lldms  %s%s%s",
                   col(C::GRN), o.port, col(C::RST),
                   o.connect_ms,
                   col(C::DIM), hint[0]?hint:"-", col(C::RST));
            if (!o.banner.empty()) {
                printf("  %sbanner:%s %s",
                       col(C::CYN), col(C::RST),
                       printable_prefix(o.banner, 60).c_str());
            }
            printf("\n");
        }
    }

    // 4) UDP probes
    printf("\n%s[4/7] UDP probes%s\n", col(C::BOLD), col(C::RST));
    auto udp_show = [&](int port, const char* name, UdpResult u){
        const char* c = u.responded ? col(C::GRN) : col(C::DIM);
        printf("  %sUDP:%-5d%s  %-18s  ",
               c, port, col(C::RST), name);
        if (u.responded) printf("%sRESP %dB%s  %s", col(C::GRN), u.bytes, col(C::RST), u.reply_hex.c_str());
        else             printf("%sno answer (%s)%s", col(C::DIM), u.err.empty()?"closed/filtered":u.err.c_str(), col(C::RST));
        printf("\n");
        R.udp_probes.push_back({port, u});
    };
    udp_show(53,    "DNS query",         dns_probe(R.dns.primary_ip, 53));
    udp_show(500,   "IKEv2 SA_INIT",     ike_probe(R.dns.primary_ip, 500));
    udp_show(4500,  "IKEv2 NAT-T",       ike_probe(R.dns.primary_ip, 4500));
    udp_show(1194,  "OpenVPN HARD_RESET",openvpn_probe(R.dns.primary_ip, 1194));
    udp_show(443,   "QUIC v1 Initial",   quic_probe(R.dns.primary_ip, 443));
    R.quic = R.udp_probes.back().second;
    udp_show(51820, "WireGuard handshake", wireguard_probe(R.dns.primary_ip, 51820));
    udp_show(41641, "Tailscale handshake", wireguard_probe(R.dns.primary_ip, 41641));

    // 5) Fingerprint per open TCP port
    printf("\n%s[5/7] Service fingerprints per open port%s\n", col(C::BOLD), col(C::RST));
    auto is_tls_port = [](int p){
        return p==443||p==4433||p==4443||p==8443||p==8080||p==8843||p==8444
             ||p==9443||p==10443||p==14443||p==20443||p==21443||p==22443||p==50443||p==51443||p==55443
             ||p==2083||p==2087||p==2096||p==6443||p==7443||p==853;
    };
    for (auto& o: R.open_tcp) {
        FullReport::PortFp pf; pf.port = o.port;
        bool printed = false;
        auto line = [&](const FpResult& f){
            printed = true;
            printf("  %s:%-5d%s  %s%-16s%s  %s",
                   col(C::CYN), o.port, col(C::RST),
                   col(C::BOLD), f.service.c_str(), col(C::RST),
                   f.details.c_str());
            if (f.is_vpn_like) printf("  %s[vpn-like]%s", col(C::YEL), col(C::RST));
            printf("\n");
            pf.fp = f;
        };
        // SSH banner (22/2222/22222)
        if (starts_with(o.banner, "SSH-") || o.port==22 || o.port==2222 || o.port==22222) {
            line(fp_ssh(o.banner, R.dns.primary_ip, o.port));
        }
        // TLS ports
        if (is_tls_port(o.port)) {
            TlsProbe tp = tls_probe(R.dns.primary_ip, o.port, R.dns.host);
            if (tp.ok) {
                FpResult f; f.service = "TLS";
                f.details = tp.version + " / " + tp.cipher + " / ALPN=" +
                            (tp.alpn.empty()?"-":tp.alpn) + " / " + tp.group +
                            " / " + std::to_string(tp.handshake_ms) + "ms" +
                            " | cert: " + printable_prefix(tp.cert_subject, 70);
                line(f);
                pf.tls = tp;
                // SNI consistency
                SniConsistency sc = sni_consistency(R.dns.primary_ip, o.port, R.dns.host);
                pf.sni = sc;
                if (sc.reality_like) {
                    printf("        %sSNI steering: same cert returned for ALL foreign SNIs, and cert is valid for '%s' -> Reality/XTLS pattern%s\n",
                           col(C::GRN), sc.matched_foreign_sni.c_str(), col(C::RST));
                } else if (sc.default_cert_only) {
                    printf("        %sSNI behaviour: single default cert returned regardless of SNI (plain server, not Reality)%s\n",
                           col(C::CYN), col(C::RST));
                } else if (sc.same_cert_always) {
                    printf("        %sSNI behaviour: identical cert across SNIs, but cert does not cover any foreign SNI (inconclusive)%s\n",
                           col(C::YEL), col(C::RST));
                } else {
                    printf("        %sSNI behaviour: cert varies per SNI (normal multi-tenant TLS, not Reality)%s\n",
                           col(C::YEL), col(C::RST));
                }
                if (!sc.base_sha.empty()) {
                    printf("        cert-sha256: %s%.16s...%s  issuer: %s\n",
                           col(C::DIM), sc.base_sha.c_str(), col(C::RST),
                           printable_prefix(tp.cert_issuer, 60).c_str());
                }
            } else {
                FpResult f; f.service = "TLS-FAIL";
                f.details = tp.err;
                line(f);
                pf.tls = tp; // keep probe even on failure (ok=false) for verdict logic
            }
        }
        // HTTP
        if (o.port==80||o.port==8080||o.port==8000||o.port==8088||o.port==8880||
            o.port==8888||o.port==81||o.port==3128||o.port==8118||o.port==8123) {
            FpResult hp = fp_http_plain(R.dns.primary_ip, o.port);
            if (!hp.details.empty() || hp.silent) line(hp);
            // proxy test
            FpResult pp = fp_http_connect(R.dns.primary_ip, o.port);
            if (pp.service == "HTTP-PROXY") line(pp);
        }
        // SOCKS
        if (o.port==1080||o.port==1081||o.port==1082||o.port==9050||
            o.port==10808||o.port==10810||o.port==7890||o.port==7891) {
            line(fp_socks5(R.dns.primary_ip, o.port));
        }
        // Shadowsocks-style (8388, 8488, 443-like with empty ALPN)
        if (o.port==8388||o.port==8488||o.port==8787||o.port==8989) {
            line(fp_shadowsocks(R.dns.primary_ip, o.port));
        }
        if (!printed) {
            FpResult g; g.service = "unknown";
            if (!o.banner.empty()) g.details = "banner: " + printable_prefix(o.banner, 70);
            else                   g.details = "open but silent on connect (ambiguous: firewalled service / Shadowsocks / Trojan / Reality wrapper — inconclusive without protocol match)";
            // skip spammy unknown unless banner present OR <20 ports total
            if (!o.banner.empty() || R.open_tcp.size() < 20) line(g);
            else pf.fp = g;
        }
        R.fps.push_back(std::move(pf));
    }

    // 6) J3 active probing on each TLS-like port
    printf("\n%s[6/7] J3 / TSPU active probing%s\n", col(C::BOLD), col(C::RST));
    for (auto& o: R.open_tcp) {
        if (!is_tls_port(o.port) && o.port != 80 && o.port != 8080) continue;
        printf("  %s-> port :%d%s\n", col(C::BOLD), o.port, col(C::RST));
        auto probes = j3_probes(R.dns.primary_ip, o.port);
        int silent = 0, resp = 0;
        for (auto& p: probes) {
            const char* c = p.responded ? col(C::YEL) : col(C::GRN);
            const char* tag = p.responded ? "RESP" : "SILENT";
            printf("     %s%-7s%s  %-28s  ", c, tag, col(C::RST), p.name.c_str());
            if (p.responded) {
                printf("%dB  %s  [%s]", p.bytes,
                       printable_prefix(p.first_line, 50).c_str(),
                       p.hex_head.c_str());
                ++resp;
            } else {
                printf("(dropped)");
                ++silent;
            }
            printf("\n");
        }
        // attach
        for (auto& pf: R.fps) if (pf.port == o.port) { pf.j3 = std::move(probes); break; }
        const char* verdict;
        // NB: silent-on-junk is not a positive ID — ANY strict TLS endpoint
        // (nginx, Apache, CDN, etc.) drops HTTP/junk before the TLS record
        // layer. Treat it as ambiguous; only name Reality via the cert-
        // steering check in the verdict engine.
        if (silent >= 6)      verdict = "silent-on-junk (TLS-only / Reality-hidden / firewalled — ambiguous)";
        else if (resp >= 6)   verdict = "responds to arbitrary bytes (plaintext HTTP-style origin)";
        else if (silent >= 3) verdict = "mixed: partly strict, partly permissive";
        else                  verdict = "mixed behaviour";
        printf("     %s-> %s%s  (silent=%d / resp=%d)\n",
               col(C::MAG), verdict, col(C::RST), silent, resp);
    }

    // 7) Verdict engine
    //
    // Design goal: never upgrade a weak soft-signal ("silent on junk") into
    // a positive stack identification. A stack is only named when a strong
    // protocol-level signature is present (e.g. Reality cert-steering +
    // TLS handshake, OpenVPN wire protocol on UDP, WireGuard default port
    // answering its handshake, etc.).
    //
    // Scoring semantics:
    //   100 = no protocol-level VPN/proxy signature found
    //    <  = penalties for every identifying pattern (VPN-flag in GeoIP,
    //         exposed proxy, plaintext VPN, weak TLS, etc.)
    //   Reality adds *penalties* too — being cleanly identifiable as
    //   Reality still counts as detectable, just not as hard as plaintext
    //   OpenVPN/WireGuard.
    // ------------------------------------------------------------------
    printf("\n%s[7/7] Verdict%s\n", col(C::BOLD), col(C::RST));
    int score = 100;
    vector<string> stack;
    vector<std::pair<int,string>> port_roles; // (port, role label)
    bool xray_reality_primary = false, xray_reality_hidden = false;
    int  reality_port_count   = 0;

    // ---- GeoIP signals ----------------------------------------------
    for (auto& g: R.geos) {
        if (g.is_hosting) score -= 5;
        if (g.is_vpn)     { score -= 15; stack.push_back("flagged as VPN by " + g.source); }
        if (g.is_proxy)   { score -= 10; stack.push_back("flagged as proxy by " + g.source); }
        if (g.is_tor)     { score -= 20; stack.push_back("flagged as Tor exit by " + g.source); }
    }
    if (R.geos.size() >= 2 && !R.geos[0].country_code.empty() && !R.geos[1].country_code.empty()
        && R.geos[0].country_code != R.geos[1].country_code) {
        score -= 5;
        stack.push_back("country-code mismatch between GeoIP sources");
    }

    // ---- TCP exposure signals ---------------------------------------
    set<int> openset;
    for (auto& o: R.open_tcp) openset.insert(o.port);
    if (openset.count(22))   { score -= 5;  stack.push_back("SSH/22 exposed (ASN classifier marks host as VPS/server)"); }
    if (openset.count(3389)) { score -= 10; stack.push_back("RDP/3389 exposed to Internet (attack surface)"); }
    if (openset.count(80))   stack.push_back("HTTP/80 open (normal for a public web-front)");
    if (openset.count(443))  stack.push_back("HTTPS/443 open (normal for a public web-front)");
    if (openset.count(1080) || openset.count(1081))
        { stack.push_back("SOCKS5 exposed without wrapper"); score -= 15; }
    if (openset.count(3128) || openset.count(8080) || openset.count(8118))
        { stack.push_back("HTTP proxy exposed without wrapper"); score -= 10; }
    if (openset.count(1194)) { stack.push_back("OpenVPN TCP/1194 (default OpenVPN port)"); score -= 15; }
    if (openset.count(8388) || openset.count(8488))
        { stack.push_back("Shadowsocks default port exposed"); score -= 15; }
    if (openset.count(10808) || openset.count(10809) || openset.count(10810))
        { stack.push_back("v2ray/xray local-style inbound port exposed to WAN"); score -= 10; }

    // ---- UDP handshake signals --------------------------------------
    for (auto& [p,u]: R.udp_probes) {
        if (!u.responded) continue;
        if (p == 1194)  { stack.push_back("OpenVPN UDP/1194 reflects HARD_RESET (protocol-level match)"); score -= 20; }
        if (p == 500)   { stack.push_back("IKEv2 responder on UDP/500"); score -= 5; }
        if (p == 4500)  { stack.push_back("IKEv2 NAT-T responder on UDP/4500"); score -= 5; }
        if (p == 51820) { stack.push_back("WireGuard default port UDP/51820 answers handshake"); score -= 15; }
        if (p == 41641) { stack.push_back("Tailscale default port UDP/41641 answers"); score -= 5; }
        if (p == 443)   stack.push_back("QUIC/HTTP3 on UDP/443 (expected for HTTP3/CDN)");
    }

    // ---- TLS posture -------------------------------------------------
    bool any_tls = false, any_reality = false, plain_tls_on_443 = false;
    for (auto& pf: R.fps) {
        if (pf.tls && pf.tls->ok) {
            any_tls = true;
            if (pf.tls->version != "TLSv1.3") { score -= 5; stack.push_back("TLS < 1.3 on :"+std::to_string(pf.port)); }
            if (pf.tls->alpn != "h2")          stack.push_back("ALPN != h2 on :"+std::to_string(pf.port));
            if (pf.tls->group != "X25519")     stack.push_back("key-exchange group != X25519 on :"+std::to_string(pf.port));
        }
        if (pf.sni && pf.sni->reality_like) {
            any_reality = true;
            ++reality_port_count;
            // Reality IS identifiable — the very fact we can recognise it
            // as Reality means a DPI engine can too. Apply a small penalty.
            score -= 5;
        }
    }

    // ---- J3 active-probe roles --------------------------------------
    for (auto& pf: R.fps) {
        if (pf.j3.size() < 6) continue;
        int sil = 0, rsp = 0;
        for (auto& j: pf.j3) { if (j.responded) ++rsp; else ++sil; }
        bool has_reality = pf.sni && pf.sni->reality_like;
        bool tls_ok      = pf.tls && pf.tls->ok;
        bool tls_failed  = pf.tls && !pf.tls->ok;

        if (has_reality && tls_ok) {
            if (sil >= 6) {
                port_roles.push_back({pf.port,
                    "Reality (hidden-mode: silent-on-junk — strong DPI signature)"});
                xray_reality_hidden = true;
                score -= 3;
            } else if (rsp >= 4) {
                port_roles.push_back({pf.port,
                    "Reality + HTTP fallback (mimics real web server on junk)"});
                xray_reality_primary = true;
                // no extra penalty: best-practice Reality configuration
            } else {
                port_roles.push_back({pf.port, "Reality (TLS endpoint)"});
            }
        } else if (tls_ok) {
            // Plain TLS server — NOT Reality.
            if (pf.port == 443) plain_tls_on_443 = true;
            if (rsp >= 7)
                port_roles.push_back({pf.port, "generic HTTPS / CDN (not Reality)"});
            else
                port_roles.push_back({pf.port, "TLS endpoint (not Reality)"});
        } else if (tls_failed && sil >= 6) {
            // Silent-on-junk with a failed TLS handshake: high ambiguity.
            // Could be Reality strict-mode, Shadowsocks AEAD, Trojan, or a
            // firewalled service. Do NOT claim Reality without the cert
            // fingerprint evidence. Report as ambiguous.
            port_roles.push_back({pf.port,
                "silent-on-junk (ambiguous: Reality strict / SS-AEAD / Trojan / firewall)"});
            score -= 5;
        }
    }

    // ---- SSH role classification ------------------------------------
    for (auto& o: R.open_tcp) {
        bool is_ssh_std  = (o.port==22 || o.port==2222 || o.port==22222);
        bool has_banner  = !o.banner.empty() && o.banner.rfind("SSH-",0)==0;
        if (is_ssh_std && has_banner)
            port_roles.push_back({o.port, "SSH (advertised banner, standard port)"});
        else if (has_banner && !is_ssh_std)
            port_roles.push_back({o.port, "SSH on non-standard port (banner still leaks version)"});
    }

    score = std::max(0, std::min(100, score));
    R.score = score;
    if (score >= 85)      R.label = "CLEAN";
    else if (score >= 70) R.label = "NOISY";
    else if (score >= 50) R.label = "SUSPICIOUS";
    else                  R.label = "OBVIOUSLY-VPN";

    const char* color = score>=85?C::GRN : score>=70?C::YEL : score>=50?C::YEL : C::RED;

    // ---- Stack identification (strict, no guessing) -----------------
    string stack_name;
    bool any_wg = std::any_of(R.udp_probes.begin(), R.udp_probes.end(),
                              [](auto& x){return x.first==51820 && x.second.responded;});
    bool any_ovpn_udp = std::any_of(R.udp_probes.begin(), R.udp_probes.end(),
                                    [](auto& x){return x.first==1194 && x.second.responded;});
    if (reality_port_count >= 2)
        stack_name = "Xray-core / sing-box (VLESS+Reality, multi-port)";
    else if (xray_reality_primary)
        stack_name = "Xray-core (VLESS+Reality with HTTP fallback)";
    else if (xray_reality_hidden)
        stack_name = "Xray-core (VLESS+Reality, hidden-mode)";
    else if (any_reality)
        stack_name = "Xray / Reality-compatible TLS steering";
    else if (any_ovpn_udp || openset.count(1194) || openset.count(1193))
        stack_name = "OpenVPN (plaintext wire protocol)";
    else if (any_wg)
        stack_name = "WireGuard (default UDP port)";
    else if (openset.count(8388) || openset.count(8488))
        stack_name = "Shadowsocks (naked default port)";
    else if (any_tls && openset.count(443))
        stack_name = "generic TLS / HTTPS origin (no VPN signature)";
    else
        stack_name = "no VPN protocol signature identified";

    printf("\n  %sStack identified:%s  %s%s%s\n",
           col(C::BOLD), col(C::RST),
           col(C::CYN), stack_name.c_str(), col(C::RST));

    if (!port_roles.empty()) {
        printf("\n  %sPer-port classification:%s\n", col(C::BOLD), col(C::RST));
        for (auto& [p, role]: port_roles)
            printf("    :%-5d  %s\n", p, role.c_str());
    }

    printf("\n  %sAdditional signals:%s\n", col(C::BOLD), col(C::RST));
    if (stack.empty()) printf("    (none — no additional red flags)\n");
    else for (auto& s: stack) printf("    - %s\n", s.c_str());

    printf("\n  %sFinal score:%s %s%d/100%s  verdict: %s%s%s\n",
           col(C::BOLD), col(C::RST), col(C::BOLD), score, col(C::RST),
           col(color), R.label.c_str(), col(C::RST));

    // ---- Technical recommendations ----------------------------------
    printf("\n  %sRecommendations:%s\n", col(C::BOLD), col(C::RST));
    bool any_advice = false;

    if (xray_reality_primary && xray_reality_hidden) {
        printf("    [!] Mixed Reality configuration: one port uses HTTP-fallback, another is hidden-mode.\n"
               "        The hidden port exposes the silent-on-junk DPI signature. Either drop the duplicate\n"
               "        listener or configure the Reality `fallback` block so it returns HTTP 400/502 on\n"
               "        non-handshake traffic, matching nginx/Apache defaults.\n");
        any_advice = true;
    } else if (xray_reality_hidden) {
        printf("    [!] Reality is in hidden-mode: handshake ok, but HTTP/junk bytes are silently dropped.\n"
               "        That 'silent-on-junk' pattern is DPI-detectable (TSPU/GFW already fingerprint it).\n"
               "        Point `dest=` at a real HTTPS site you do NOT control and configure `fallback`\n"
               "        so the server returns its 400/502 page on unrecognised bytes.\n");
        any_advice = true;
    } else if (xray_reality_primary) {
        printf("    [+] Reality HTTP-fallback is wired correctly: non-handshake bytes get an HTTP 400,\n"
               "        which is indistinguishable from a vanilla nginx/Apache reverse-proxy. No action needed.\n");
        any_advice = true;
    }
    if (reality_port_count >= 2) {
        printf("    [-] Reality is listening on %d ports of the same IP. ASN/port sweeps will flag\n"
               "        multi-port TLS-steering anomalies; keep Reality on a single port and populate\n"
               "        the other ports with real services (or close them).\n", reality_port_count);
        any_advice = true;
    }
    if (plain_tls_on_443 && !any_reality) {
        printf("    [i] Port 443 serves a plain TLS origin with a single default cert: looks like any\n"
               "        nginx/Apache/CDN origin — no VPN signature visible from outside.\n");
        any_advice = true;
    }
    if (any_tls && !any_reality) {
        // Neutral informational — no penalty was applied above.
    }
    if (openset.count(22)) {
        printf("    [-] Close or rehome SSH/22: the open SSH banner is sufficient for any ASN aggregator\n"
               "        to classify the host as VPS/server. Move it to a non-standard port AND\n"
               "        firewall it to known admin source IPs.\n");
        any_advice = true;
    }
    if (any_ovpn_udp || openset.count(1194) || openset.count(1193)) {
        printf("    [!] OpenVPN on the default port 1194: TSPU/GFW drop this on the first HARD_RESET.\n"
               "        Wrap in TLS (Cloak, stunnel, or migrate to VLESS+Reality on 443).\n");
        any_advice = true;
    }
    if (any_wg) {
        printf("    [!] WireGuard on UDP/51820 answers its handshake: the handshake itself is a\n"
               "        distinctive fixed-offset signature. Use amneziawg or put WireGuard behind\n"
               "        a TCP-TLS tunnel if you need to survive active DPI.\n");
        any_advice = true;
    }
    if (openset.count(8388) || openset.count(8488)) {
        printf("    [!] Shadowsocks on its default port is trivially probed via AEAD-length oracle.\n"
               "        Wrap it with v2ray/xray stream settings + TLS, or drop it for VLESS+Reality.\n");
        any_advice = true;
    }
    if (openset.count(3389)) {
        printf("    [!] RDP/3389 is reachable from the Internet: this is a critical attack surface.\n"
               "        Firewall it immediately; expose it only through a VPN or jump host.\n");
        any_advice = true;
    }
    for (auto& pf: R.fps)
        if (pf.tls && pf.tls->ok && pf.tls->version != "TLSv1.3") {
            printf("    [-] Upgrade TLS to 1.3 on :%d (current: %s). Modern Reality/VLESS requires 1.3.\n",
                   pf.port, pf.tls->version.c_str());
            any_advice = true;
        }
    if (!any_advice)
        printf("    (none — no actionable red flags detected)\n");

    return R;
}

// ============================================================================
// CLI helpers
// ============================================================================
static void help() {
    printf("ByeByeVPN — full TSPU/DPI/VPN detectability scanner\n\n");
    printf("Usage:\n");
    printf("  byebyevpn                      interactive menu\n");
    printf("  byebyevpn <ip-or-host>         full scan (recommended)\n");
    printf("  byebyevpn scan <ip>            full scan same\n");
    printf("  byebyevpn ports <ip>           TCP port scan only\n");
    printf("  byebyevpn udp <ip>             UDP probes only\n");
    printf("  byebyevpn tls <ip> [port]      TLS + SNI consistency only\n");
    printf("  byebyevpn j3 <ip> [port]       J3 active probing only\n");
    printf("  byebyevpn geoip <ip>           GeoIP only\n");
    printf("  byebyevpn local                scan THIS machine (split-tunnel / VPN procs)\n\n");
    printf("Port-scan modes (default: --full):\n");
    printf("  --full              scan ALL ports 1-65535  (default)\n");
    printf("  --fast              205 curated VPN/proxy/TLS/admin ports\n");
    printf("  --range 1000-2000   scan a port range\n");
    printf("  --ports 80,443,8443 scan explicit port list\n\n");
    printf("Tuning:\n");
    printf("  --threads N     parallel TCP connects   (default 500)\n");
    printf("  --tcp-to MS     TCP connect timeout      (default 800)\n");
    printf("  --udp-to MS     UDP recv timeout         (default 900)\n");
    printf("  --no-color      disable ANSI colors\n");
    printf("  -v / --verbose  verbose\n\n");
    printf("GeoIP sources: ipapi.is, iplocate.io, ip-api.com, ipwho.is,\n");
    printf("               ipinfo.io, freeipapi.com, 2ip.io (RU)\n");
}

static void pause_for_enter() {
    printf("\n%s[Enter] to continue...%s", col(C::DIM), col(C::RST));
    fflush(stdout);
    int c; while ((c = getchar()) != EOF && c != '\n') {}
}

static string ask(const string& prompt) {
    printf("%s", prompt.c_str()); fflush(stdout);
    char buf[256] = {0};
    if (!fgets(buf, sizeof(buf), stdin)) return {};
    return trim(buf);
}

static void interactive() {
    for (;;) {
        system("cls");
        banner();
        printf("  %s[1]%s  Full scan             — end-to-end scan of an IP/hostname\n", col(C::CYN), col(C::RST));
        printf("  %s[2]%s  TCP port scan         — TCP port-scan only\n", col(C::CYN), col(C::RST));
        printf("  %s[3]%s  UDP probes            — OpenVPN / WireGuard / IKE / QUIC / DNS\n", col(C::CYN), col(C::RST));
        printf("  %s[4]%s  TLS + SNI consistency — TLS audit on a single port (Reality discriminator)\n", col(C::CYN), col(C::RST));
        printf("  %s[5]%s  J3 active probing     — TSPU/GFW-style probes on one port\n", col(C::CYN), col(C::RST));
        printf("  %s[6]%s  GeoIP lookup          — country / ASN / VPN-flag aggregation\n", col(C::CYN), col(C::RST));
        printf("  %s[7]%s  Local analysis        — this machine: VPN adapters, split-tunnel, processes\n", col(C::CYN), col(C::RST));
        printf("  %s[0]%s  Exit\n\n", col(C::CYN), col(C::RST));
        string s = ask("  > ");
        if (s.empty()) continue;
        char c = s[0];
        if (c == '0' || c == 'q' || c == 'Q') break;
        else if (c == '1') {
            string t = ask("  target (IP or hostname): ");
            if (!t.empty()) run_full_target(t);
            pause_for_enter();
        } else if (c == '2') {
            string t = ask("  target IP: ");
            if (!t.empty()) {
                auto rs = resolve_host(t);
                auto op = scan_tcp(rs.primary_ip.empty()?t:rs.primary_ip, build_tcp_ports(), g_threads, g_tcp_to);
                for (auto& o: op) printf("  :%-5d  %lldms  %s%s\n", o.port, o.connect_ms,
                                          port_hint(o.port), o.banner.empty()?"":(" banner="+printable_prefix(o.banner,60)).c_str());
            }
            pause_for_enter();
        } else if (c == '3') {
            string t = ask("  target IP: ");
            if (!t.empty()) {
                auto rs = resolve_host(t); string ip = rs.primary_ip.empty()?t:rs.primary_ip;
                auto show=[&](const char*n,int p,UdpResult u){
                    printf("  UDP:%-5d  %-22s  %s\n", p, n,
                        u.responded?("RESP "+std::to_string(u.bytes)+"B "+u.reply_hex).c_str()
                                    :("no answer ("+u.err+")").c_str());
                };
                show("DNS",       53,    dns_probe(ip,53));
                show("IKEv2",     500,   ike_probe(ip,500));
                show("IKE NAT-T", 4500,  ike_probe(ip,4500));
                show("OpenVPN",   1194,  openvpn_probe(ip,1194));
                show("QUIC",      443,   quic_probe(ip,443));
                show("WireGuard", 51820, wireguard_probe(ip,51820));
                show("Tailscale", 41641, wireguard_probe(ip,41641));
            }
            pause_for_enter();
        } else if (c == '4') {
            string t = ask("  target host (used as SNI): ");
            string ps = ask("  port (default 443): ");
            int port = ps.empty() ? 443 : atoi(ps.c_str());
            if (!t.empty()) {
                auto rs = resolve_host(t);
                string ip = rs.primary_ip.empty()?t:rs.primary_ip;
                auto tp = tls_probe(ip, port, t);
                if (!tp.ok) printf("  TLS fail: %s\n", tp.err.c_str());
                else {
                    printf("  %s%s%s / %s / ALPN=%s / %s / %lldms\n",
                           col(C::BOLD), tp.version.c_str(), col(C::RST),
                           tp.cipher.c_str(), tp.alpn.c_str(), tp.group.c_str(), tp.handshake_ms);
                    printf("  cert: %s\n", tp.cert_subject.c_str());
                    printf("  issuer: %s\n", tp.cert_issuer.c_str());
                    printf("  sha256: %s\n", tp.cert_sha256.c_str());
                    auto sc = sni_consistency(ip, port, t);
                    for (auto& e: sc.entries)
                        printf("    alt SNI %-35s  %s  %s\n",
                               e.sni.c_str(),
                               e.ok ? ("sha:"+e.sha.substr(0,16)).c_str() : "fail",
                               (e.ok && e.sha == sc.base_sha) ? "SAME" : "diff");
                    if (sc.reality_like)
                        printf("  %s=> Reality/XTLS pattern: cert covers foreign SNI '%s'%s\n",
                               col(C::GRN), sc.matched_foreign_sni.c_str(), col(C::RST));
                    else if (sc.default_cert_only)
                        printf("  %s=> plain TLS server with a single default cert (NOT Reality)%s\n",
                               col(C::CYN), col(C::RST));
                    else if (sc.same_cert_always)
                        printf("  %s=> identical cert for all SNIs but covers no foreign SNI (inconclusive)%s\n",
                               col(C::YEL), col(C::RST));
                    else
                        printf("  %s=> cert varies per SNI (multi-tenant TLS, NOT Reality)%s\n",
                               col(C::YEL), col(C::RST));
                }
            }
            pause_for_enter();
        } else if (c == '5') {
            string t = ask("  target IP: ");
            string ps = ask("  port: ");
            if (!t.empty() && !ps.empty()) {
                int port = atoi(ps.c_str());
                auto rs = resolve_host(t); string ip = rs.primary_ip.empty()?t:rs.primary_ip;
                auto probes = j3_probes(ip, port);
                for (auto& p: probes) {
                    printf("  %-30s  %s  %dB %s\n", p.name.c_str(),
                        p.responded?"RESP":"SILENT",
                        p.bytes,
                        p.responded ? printable_prefix(p.first_line,60).c_str() : "(dropped)");
                }
            }
            pause_for_enter();
        } else if (c == '6') {
            string t = ask("  IP (blank = your IP): ");
            auto f1 = std::async(std::launch::async, geo_ipapi_is,   t);
            auto f2 = std::async(std::launch::async, geo_iplocate,   t);
            auto f3 = std::async(std::launch::async, geo_ip_api_com, t);
            auto f4 = std::async(std::launch::async, geo_ipwho_is,   t);
            auto f5 = std::async(std::launch::async, geo_ipinfo_io,  t);
            auto f6 = std::async(std::launch::async, geo_freeipapi,  t);
            auto f7 = std::async(std::launch::async, geo_2ip_ru,     t);
            print_geo(f1.get()); print_geo(f2.get()); print_geo(f3.get());
            print_geo(f4.get()); print_geo(f5.get()); print_geo(f6.get());
            print_geo(f7.get());
            pause_for_enter();
        } else if (c == '7') {
            run_local_analysis();
            pause_for_enter();
        }
    }
}

// ============================================================================
// main
// ============================================================================
int main(int argc, char** argv) {
    enable_vt();
    WSADATA ws; WSAStartup(MAKEWORD(2,2), &ws);
    SSL_library_init(); SSL_load_error_strings();
    OpenSSL_add_all_algorithms();
    srand((unsigned)time(nullptr));

    vector<string> pos;
    for (int i=1;i<argc;++i) {
        string a = argv[i];
        if (a == "--no-color") g_no_color = true;
        else if (a == "--verbose" || a == "-v") g_verbose = true;
        else if (a == "--threads" && i+1<argc) g_threads = atoi(argv[++i]);
        else if (a == "--tcp-to" && i+1<argc)  g_tcp_to  = atoi(argv[++i]);
        else if (a == "--udp-to" && i+1<argc)  g_udp_to  = atoi(argv[++i]);
        else if (a == "--full")  g_port_mode = PortMode::FULL;
        else if (a == "--fast")  g_port_mode = PortMode::FAST;
        else if (a == "--range" && i+1<argc) {
            string v = argv[++i];
            size_t dash = v.find('-');
            if (dash != string::npos) {
                g_range_lo = atoi(v.substr(0, dash).c_str());
                g_range_hi = atoi(v.substr(dash+1).c_str());
                g_port_mode = PortMode::RANGE;
            }
        }
        else if (a == "--ports" && i+1<argc) {
            string v = argv[++i]; g_port_list.clear();
            size_t p = 0;
            while (p < v.size()) {
                size_t c = v.find(',', p);
                string tok = v.substr(p, c==string::npos?string::npos:c-p);
                if (!tok.empty()) g_port_list.push_back(atoi(tok.c_str()));
                if (c==string::npos) break;
                p = c+1;
            }
            if (!g_port_list.empty()) g_port_mode = PortMode::LIST;
        }
        else if (a == "--help" || a == "-h" || a == "/?") { help(); return 0; }
        else pos.push_back(a);
    }

    banner();
    int rc = 0;
    if (pos.empty()) {
        interactive();
    } else {
        string cmd = pos[0];
        if (cmd == "scan" || cmd == "full") {
            if (pos.size() < 2) { printf("need target\n"); return 2; }
            run_full_target(pos[1]);
        } else if (cmd == "ports") {
            if (pos.size() < 2) { printf("need target\n"); return 2; }
            auto rs = resolve_host(pos[1]);
            auto op = scan_tcp(rs.primary_ip.empty()?pos[1]:rs.primary_ip, build_tcp_ports(), g_threads, g_tcp_to);
            for (auto& o: op) printf("  :%-5d  %lldms  %s\n", o.port, o.connect_ms, port_hint(o.port));
        } else if (cmd == "udp") {
            if (pos.size() < 2) { printf("need target\n"); return 2; }
            auto rs = resolve_host(pos[1]); string ip = rs.primary_ip.empty()?pos[1]:rs.primary_ip;
            auto show=[&](const char*n,int p,UdpResult u){
                printf("  UDP:%-5d  %-22s  %s\n", p, n,
                    u.responded?("RESP "+std::to_string(u.bytes)+"B "+u.reply_hex).c_str()
                                :("no answer ("+u.err+")").c_str());
            };
            show("DNS",       53,    dns_probe(ip,53));
            show("IKEv2",     500,   ike_probe(ip,500));
            show("IKE NAT-T", 4500,  ike_probe(ip,4500));
            show("OpenVPN",   1194,  openvpn_probe(ip,1194));
            show("QUIC",      443,   quic_probe(ip,443));
            show("WireGuard", 51820, wireguard_probe(ip,51820));
            show("Tailscale", 41641, wireguard_probe(ip,41641));
        } else if (cmd == "tls") {
            if (pos.size() < 2) { printf("need target\n"); return 2; }
            int port = pos.size() >= 3 ? atoi(pos[2].c_str()) : 443;
            auto rs = resolve_host(pos[1]);
            string ip = rs.primary_ip.empty()?pos[1]:rs.primary_ip;
            auto tp = tls_probe(ip, port, pos[1]);
            if (!tp.ok) { printf("TLS fail: %s\n", tp.err.c_str()); return 1; }
            printf("  %s / %s / ALPN=%s / %s / %lldms\n",
                   tp.version.c_str(), tp.cipher.c_str(), tp.alpn.c_str(),
                   tp.group.c_str(), tp.handshake_ms);
            printf("  cert:   %s\n", tp.cert_subject.c_str());
            printf("  issuer: %s\n", tp.cert_issuer.c_str());
            printf("  sha256: %s\n", tp.cert_sha256.c_str());
            auto sc = sni_consistency(ip, port, pos[1]);
            for (auto& e: sc.entries)
                printf("    %-35s  %s  %s\n", e.sni.c_str(),
                       e.ok ? ("sha:"+e.sha.substr(0,16)).c_str() : "fail",
                       (e.ok && e.sha == sc.base_sha) ? "SAME" : "diff");
            if (sc.reality_like)
                printf("  => Reality/XTLS pattern (cert covers foreign SNI '%s')\n",
                       sc.matched_foreign_sni.c_str());
            else if (sc.default_cert_only)
                printf("  => plain TLS server with single default cert (NOT Reality)\n");
            else if (sc.same_cert_always)
                printf("  => identical cert across SNIs but covers no foreign SNI (inconclusive)\n");
            else
                printf("  => cert varies per SNI (multi-tenant TLS, NOT Reality)\n");
        } else if (cmd == "j3") {
            if (pos.size() < 2) { printf("need target\n"); return 2; }
            int port = pos.size() >= 3 ? atoi(pos[2].c_str()) : 443;
            auto rs = resolve_host(pos[1]); string ip = rs.primary_ip.empty()?pos[1]:rs.primary_ip;
            auto probes = j3_probes(ip, port);
            for (auto& p: probes)
                printf("  %-28s  %s  %dB %s\n", p.name.c_str(),
                    p.responded?"RESP":"SILENT", p.bytes,
                    p.responded ? printable_prefix(p.first_line,60).c_str() : "(dropped)");
        } else if (cmd == "geoip") {
            string ip = pos.size()>=2 ? pos[1] : "";
            auto f1 = std::async(std::launch::async, geo_ipapi_is,   ip);
            auto f2 = std::async(std::launch::async, geo_iplocate,   ip);
            auto f3 = std::async(std::launch::async, geo_ip_api_com, ip);
            auto f4 = std::async(std::launch::async, geo_ipwho_is,   ip);
            auto f5 = std::async(std::launch::async, geo_ipinfo_io,  ip);
            auto f6 = std::async(std::launch::async, geo_freeipapi,  ip);
            auto f7 = std::async(std::launch::async, geo_2ip_ru,     ip);
            print_geo(f1.get()); print_geo(f2.get()); print_geo(f3.get());
            print_geo(f4.get()); print_geo(f5.get()); print_geo(f6.get());
            print_geo(f7.get());
        } else if (cmd == "local" || cmd == "me" || cmd == "self") {
            run_local_analysis();
        } else if (cmd == "help" || cmd == "--help") {
            help();
        } else {
            // treat as target for full scan
            run_full_target(cmd);
        }
    }
    WSACleanup();
    return rc;
}
