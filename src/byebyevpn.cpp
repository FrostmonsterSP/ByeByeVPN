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
    printf("%s  Full TSPU/DPI/VPN detectability scanner  v2.3%s\n\n",
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

// ----------------------------------------------------------------------------
// 3 RU-facing providers — important because RU-origin GeoIP sees Russian
// hosting differently from EU/US providers (VEESP, Hostkey, Ruvds etc.)
// ----------------------------------------------------------------------------

// 2ip.me / 2ip.ru  —  Russian IP-checker (HTTPS with proper UA)
// api.2ip.me/geo.json returns 429 without a browser UA, so we go through
// the HTML-less JSON endpoint with explicit Accept/UA (http_get already
// sends Mozilla UA).
static GeoInfo geo_2ip_ru(const string& ip) {
    GeoInfo g; g.source = "2ip.ru (RU)";
    // Prefer HTTPS, fall back to HTTP. The .me endpoint tends to 429 with
    // no-key access; the /geoip/ JSON on the main domain is more lenient.
    string url = "https://2ip.io/geoip/" + ip + "/";
    auto r = http_get(url);
    if (!r.ok() || r.body.find("country") == string::npos) {
        url = "http://api.2ip.me/geo.json?ip=" + ip;
        r = http_get(url);
    }
    if (!r.ok()) { g.err = "http " + std::to_string(r.status) + " " + r.err; return g; }
    g.ip           = json_get_str(r.body, "ip");
    if (g.ip.empty()) g.ip = ip;
    g.country      = json_get_str(r.body, "country");
    if (g.country.empty()) g.country = json_get_str(r.body, "country_rus");
    if (g.country.empty()) g.country = json_get_str(r.body, "countryName");
    g.country_code = json_get_str(r.body, "country_code");
    if (g.country_code.empty()) g.country_code = json_get_str(r.body, "countryCode");
    g.city         = json_get_str(r.body, "city");
    if (g.city.empty()) g.city = json_get_str(r.body, "city_rus");
    if (g.city.empty()) g.city = json_get_str(r.body, "cityName");
    string org     = json_get_str(r.body, "org");
    if (!org.empty()) g.asn_org = org;
    return g;
}

// ip-api.com/ru  —  same backend as ip-api.com but the /ru/ path returns
// Russian-localised location strings AND carries a different endpoint-
// -tier for RU-routed clients.  We call it with a distinct source label
// so it counts as an independent RU-side opinion (they rate-limit per
// source IP per endpoint).
static GeoInfo geo_ipapi_ru(const string& ip) {
    GeoInfo g; g.source = "ip-api.com/ru (RU)";
    string url = "http://ip-api.com/json/";
    if (!ip.empty()) url += ip;
    url += "?lang=ru&fields=status,country,countryCode,city,isp,org,as,asname,hosting,proxy,mobile,query";
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

// SypexGeo — Russian GeoIP project, public API, no key needed for city-level
// lookups.  Endpoint returns JSON with country/city/lat/lon.
static GeoInfo geo_sypex(const string& ip) {
    GeoInfo g; g.source = "sypexgeo.net (RU)";
    string url = "http://api.sypexgeo.net/json/" + ip;
    auto r = http_get(url);
    if (!r.ok()) { g.err = "http " + std::to_string(r.status) + " " + r.err; return g; }
    g.ip           = ip;
    // Their JSON is nested: country.name_en, city.name_en, region.name_en
    g.country_code = json_get_str(r.body, "iso");
    // try nested
    {
        size_t cp = r.body.find("\"country\"");
        if (cp != string::npos) {
            size_t ob = r.body.find('{', cp);
            size_t ce = ob == string::npos ? string::npos : r.body.find('}', ob);
            if (ob != string::npos && ce != string::npos) {
                string sb = r.body.substr(ob, ce - ob + 1);
                g.country = json_get_str(sb, "name_en");
                if (g.country.empty()) g.country = json_get_str(sb, "name_ru");
                if (g.country_code.empty()) g.country_code = json_get_str(sb, "iso");
            }
        }
    }
    {
        size_t cp = r.body.find("\"city\"");
        if (cp != string::npos) {
            size_t ob = r.body.find('{', cp);
            size_t ce = ob == string::npos ? string::npos : r.body.find('}', ob);
            if (ob != string::npos && ce != string::npos) {
                string sb = r.body.substr(ob, ce - ob + 1);
                g.city = json_get_str(sb, "name_en");
                if (g.city.empty()) g.city = json_get_str(sb, "name_ru");
            }
        }
    }
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
    // v2.2 — richer cert intel for red-flag accumulation
    string  subject_cn;      // CN only (for short display)
    string  issuer_cn;       // issuer CN only
    int     age_days = 0;    // today - notBefore  (negative if not yet valid)
    int     days_left = 0;   // notAfter - today   (negative if expired)
    int     total_validity_days = 0;
    bool    self_signed = false;
    bool    is_letsencrypt = false;  // LE / ZeroSSL / Buypass — free-CA family
    bool    is_wildcard = false;     // any *.foo in SAN or CN
    int     san_count = 0;
};

static int asn1_time_diff_days_now(const ASN1_TIME* t, bool from_t_to_now) {
    if (!t) return 0;
    int day = 0, sec = 0;
    if (from_t_to_now) ASN1_TIME_diff(&day, &sec, t, nullptr);
    else               ASN1_TIME_diff(&day, &sec, nullptr, t);
    return day;
}

static string extract_cn_from_subject(const string& subj) {
    size_t p = subj.find("CN=");
    if (p == string::npos) return {};
    p += 3;
    size_t e = subj.find_first_of("/,", p);
    return subj.substr(p, e == string::npos ? string::npos : e - p);
}

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
        r.subject_cn   = extract_cn_from_subject(r.cert_subject);
        r.issuer_cn    = extract_cn_from_subject(r.cert_issuer);
        r.self_signed  = !r.cert_subject.empty() && r.cert_subject == r.cert_issuer;
        // free-CA family commonly used by disposable proxy hosts
        {
            const string& iss = r.cert_issuer;
            r.is_letsencrypt =
                iss.find("Let's Encrypt") != string::npos ||
                iss.find("R3") != string::npos || iss.find("R10") != string::npos ||
                iss.find("R11") != string::npos || iss.find("E5") != string::npos ||
                iss.find("E6") != string::npos ||
                iss.find("ZeroSSL") != string::npos ||
                iss.find("Buypass") != string::npos ||
                iss.find("Google Trust Services") != string::npos;
        }
        unsigned char dgst[32]; unsigned dl = 0;
        X509_digest(cert, EVP_sha256(), dgst, &dl);
        r.cert_sha256 = hex_s(dgst, dl);
        // cert validity
        const ASN1_TIME* nb = X509_get0_notBefore(cert);
        const ASN1_TIME* na = X509_get0_notAfter(cert);
        r.age_days  = asn1_time_diff_days_now(nb, true);    // nb -> now
        r.days_left = asn1_time_diff_days_now(na, false);   // now -> na
        if (nb && na) {
            int d=0, s=0; ASN1_TIME_diff(&d, &s, nb, na); r.total_validity_days = d;
        }
        GENERAL_NAMES* gens = (GENERAL_NAMES*)X509_get_ext_d2i(cert, NID_subject_alt_name, nullptr, nullptr);
        if (gens) {
            int nn = sk_GENERAL_NAME_num(gens);
            for (int i=0;i<nn;++i) {
                GENERAL_NAME* g = sk_GENERAL_NAME_value(gens, i);
                if (g->type == GEN_DNS) {
                    unsigned char* us = nullptr;
                    int ul = ASN1_STRING_to_UTF8(&us, g->d.dNSName);
                    if (ul > 0) {
                        string name((char*)us, ul);
                        if (name.size() > 2 && name[0]=='*' && name[1]=='.') r.is_wildcard = true;
                        r.san.push_back(std::move(name));
                    }
                    OPENSSL_free(us);
                }
            }
            GENERAL_NAMES_free(gens);
        }
        r.san_count = (int)r.san.size();
        if (!r.is_wildcard && !r.subject_cn.empty() && r.subject_cn.size() > 2 &&
            r.subject_cn[0] == '*' && r.subject_cn[1] == '.') r.is_wildcard = true;
        X509_free(cert);
    }
    SSL_shutdown(ssl);
    SSL_free(ssl); SSL_CTX_free(ctx); closesocket(s);
    r.handshake_ms = std::chrono::duration_cast<std::chrono::milliseconds>(
                       std::chrono::steady_clock::now() - t0).count();
    return r;
}

// ============================================================================
// Brand-cert impersonation detection  (v2.3)
//
// Classical Xray/VLESS+Reality "static dest" setup: the operator sets
// `dest=www.amazon.com:443` in Reality config, so when ANY SNI-less TLS
// client connects, the Reality listener proxies the handshake to the real
// amazon.com and forwards amazon's cert back to us. Result: a random VPS
// in US on AS56971 CGI GLOBAL LIMITED returns CN=www.amazon.com. That's
// NOT "plain server" — that's impersonation, which is also the exact
// Reality-static profile TSPU/GFW fingerprint.
//
// We detect this by cross-referencing:
//   (a) cert CN / SAN list against a curated list of famous brand domains
//   (b) ASN-org strings against a list of markers that would legitimately
//       own those brands
//
// If a brand cert is served but the ASN clearly doesn't belong to that
// brand, it's impersonation.
// ============================================================================
struct BrandMarker {
    const char* brand;        // the domain the cert claims
    const char* asn_markers;  // comma-separated ASN-org substrings that
                              // legitimately run this brand's endpoints
};
static const BrandMarker BRAND_TABLE[] = {
    {"amazon.com",     "amazon,aws,a100 row,amazon technologies"},
    {"aws.amazon.com", "amazon,aws"},
    {"microsoft.com",  "microsoft,msn,msft,akamai,edgecast"},
    {"apple.com",      "apple,akamai"},
    {"google.com",     "google,gts,gcp,youtube"},
    {"googleusercontent.com", "google,gcp"},
    {"youtube.com",    "google,youtube"},
    {"cloudflare.com", "cloudflare,cloudflare inc"},
    {"github.com",     "github,microsoft,fastly"},
    {"yandex.ru",      "yandex"},
    {"yandex.net",     "yandex"},
    {"yandex.com",     "yandex"},
    {"yahoo.com",      "yahoo,oath,verizon"},
    {"facebook.com",   "facebook,meta"},
    {"instagram.com",  "facebook,meta"},
    {"whatsapp.com",   "facebook,meta"},
    {"twitter.com",    "twitter,x corp"},
    {"x.com",          "twitter,x corp"},
    {"netflix.com",    "netflix,akamai"},
    {"cdn.jsdelivr.net","fastly,cloudflare"},
    {"bing.com",       "microsoft"},
    {"gstatic.com",    "google"},
    {"mail.ru",        "mail.ru,vk"},
    {"vk.com",         "vk,mail.ru"},
    {"wikipedia.org",  "wikimedia"},
    {"linkedin.com",   "linkedin,microsoft"},
    {"office.com",     "microsoft"},
    {"live.com",       "microsoft"},
};
static const size_t BRAND_TABLE_N = sizeof(BRAND_TABLE)/sizeof(BRAND_TABLE[0]);

// Returns empty if no brand match, else the brand domain the cert vouches for.
// Checks subject CN + all SAN entries.
static string cert_claims_brand(const string& subject_cn,
                                const vector<string>& san) {
    auto is_brand = [](const string& name)->const char*{
        if (name.empty()) return nullptr;
        string ln = name;
        for (auto& c: ln) c = (char)std::tolower((unsigned char)c);
        // strip leading "*." from wildcard names
        if (ln.size() > 2 && ln[0]=='*' && ln[1]=='.') ln = ln.substr(2);
        for (size_t i=0;i<BRAND_TABLE_N;++i) {
            string b = BRAND_TABLE[i].brand;
            if (ln == b) return BRAND_TABLE[i].brand;
            if (ln.size() > b.size() + 1 &&
                ln.compare(ln.size()-b.size(), b.size(), b) == 0 &&
                ln[ln.size()-b.size()-1] == '.') return BRAND_TABLE[i].brand;
        }
        return nullptr;
    };
    const char* hit = is_brand(subject_cn);
    if (hit) return hit;
    for (auto& s: san) { hit = is_brand(s); if (hit) return hit; }
    return {};
}

// Given a brand and the scanned host's GeoIP ASN-org list, return true iff
// the ASN legitimately owns the brand.
static bool asn_owns_brand(const string& brand_domain,
                           const vector<string>& asn_orgs) {
    if (brand_domain.empty() || asn_orgs.empty()) return false;
    const char* markers = nullptr;
    for (size_t i=0;i<BRAND_TABLE_N;++i) {
        if (brand_domain == BRAND_TABLE[i].brand) {
            markers = BRAND_TABLE[i].asn_markers; break;
        }
    }
    if (!markers) return false;
    string ms = markers;
    for (auto& c: ms) c = (char)std::tolower((unsigned char)c);
    vector<string> parts = split(ms, ',');
    for (auto& org: asn_orgs) {
        string lo = org;
        for (auto& c: lo) c = (char)std::tolower((unsigned char)c);
        for (auto& m: parts) {
            string mm = trim(m);
            if (!mm.empty() && lo.find(mm) != string::npos) return true;
        }
    }
    return false;
}

// Given an HTTP `Server:` header value, return the brand domain from
// BRAND_TABLE that the banner unambiguously belongs to. Only triggers on
// banners a real web server can never produce by accident — e.g.
// "CloudFront" or "AmazonS3" (never set by nginx/Apache/Caddy), "gws"
// (Google's proprietary frontend, only served by Google), etc. Empty
// return = no brand mapping.
static string server_header_brand(const string& server_hdr) {
    if (server_hdr.empty()) return {};
    string s = server_hdr;
    for (auto& c: s) c = (char)std::tolower((unsigned char)c);
    // Amazon / AWS
    if (s.find("cloudfront") != string::npos) return "amazon.com";
    if (s.find("amazons3")   != string::npos) return "amazon.com";
    if (s.find("awselb")     != string::npos) return "amazon.com";
    if (s.find("aws elb")    != string::npos) return "amazon.com";
    // Google
    if (s == "gws" || s.find("gws/") != string::npos) return "google.com";
    if (s.find("gfe/")       != string::npos) return "google.com";
    if (s.find("gse/")       != string::npos) return "google.com";
    if (s.find("esf")        != string::npos) return "google.com";
    // Cloudflare
    if (s == "cloudflare" || s.find("cloudflare-nginx") != string::npos) return "cloudflare.com";
    // Microsoft IIS / Azure
    if (s.find("microsoft-iis")    != string::npos) return "microsoft.com";
    if (s.find("microsoft-httpapi")!= string::npos) return "microsoft.com";
    // Yandex
    if (s.find("yandex")     != string::npos) return "yandex.ru";
    // Apple
    if (s.find("applehttpserver") != string::npos) return "apple.com";
    // Fastly / Akamai are CDNs without brand-table entries — skip.
    return {};
}

// ============================================================================
// Active HTTP/1.1 probe inside an established TLS session  (v2.3)
//
// After the TLS handshake succeeds we try to actually speak HTTP on it.
// A real web server (nginx/Apache/Caddy/CDN) will emit a proper HTTP/1.1
// response line with a valid version (1.0/1.1/2), a legitimate status
// code, and typically a Server: header. A stream-layer proxy (Xray/
// Trojan/SS-AEAD) either closes the stream, returns garbage, or emits
// a canned fallback like "HTTP/0.0 307 Temporary Redirect" (a classic
// Xray `fallback+redirect` signature).
// ============================================================================
struct HttpsProbe {
    bool   tls_ok   = false;
    bool   responded = false;
    int    bytes    = 0;
    string first_line;     // trimmed response line
    string server_hdr;     // Server: value
    string http_version;   // "HTTP/1.1", "HTTP/0.0" (anomaly), ...
    int    status_code = 0;
    bool   version_anomaly = false;  // HTTP/x.y with x!=1,2 or malformed
    bool   no_server_hdr   = false;  // responded but no Server: header
    string err;
};

static HttpsProbe https_probe(const string& ip, int port, const string& host_hdr,
                              int to_ms = 5000) {
    HttpsProbe r;
    string err;
    SOCKET s = tcp_connect(ip, port, to_ms, err);
    if (s == INVALID_SOCKET) { r.err = err; return r; }
    SSL_CTX* ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_min_proto_version(ctx, TLS1_2_VERSION);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    SSL* ssl = SSL_new(ctx);
    SSL_set_fd(ssl, (int)s);
    if (!host_hdr.empty()) SSL_set_tlsext_host_name(ssl, host_hdr.c_str());
    // advertise http/1.1 only so any proper server picks it
    static const unsigned char alpn_h11[] = {8,'h','t','t','p','/','1','.','1'};
    SSL_set_alpn_protos(ssl, alpn_h11, sizeof(alpn_h11));
    if (SSL_connect(ssl) != 1) {
        r.err = "tls handshake failed";
        SSL_free(ssl); SSL_CTX_free(ctx); closesocket(s);
        return r;
    }
    r.tls_ok = true;
    string req = "GET / HTTP/1.1\r\nHost: " + (host_hdr.empty()?string("example.com"):host_hdr) +
                 "\r\nUser-Agent: Mozilla/5.0 (compatible; ByeByeVPN/2.3)\r\nAccept: */*\r\n"
                 "Connection: close\r\n\r\n";
    SSL_write(ssl, req.data(), (int)req.size());
    // Collect up to ~4KB of response
    string body;
    char buf[1024];
    for (int i=0; i<6; ++i) {
        int n = SSL_read(ssl, buf, sizeof(buf));
        if (n <= 0) break;
        body.append(buf, n);
        if (body.size() >= 4096) break;
    }
    SSL_shutdown(ssl); SSL_free(ssl); SSL_CTX_free(ctx); closesocket(s);
    r.bytes = (int)body.size();
    if (body.empty()) return r;
    r.responded = true;
    size_t nl = body.find('\n');
    r.first_line = trim(body.substr(0, nl == string::npos ? body.size() : nl));
    // parse "HTTP/x.y CODE REASON"
    if (starts_with(r.first_line, "HTTP/")) {
        size_t sp = r.first_line.find(' ');
        r.http_version = r.first_line.substr(0, sp == string::npos ? r.first_line.size() : sp);
        // x.y check
        if (r.http_version.size() >= 8) {
            char x = r.http_version[5], y = r.http_version[7];
            if (!(x=='1' || x=='2') || !(y=='0' || y=='1')) r.version_anomaly = true;
            // HTTP/2.1, HTTP/3.x text, HTTP/0.0 etc. are all anomalies
            if (x=='0') r.version_anomaly = true;
        } else r.version_anomaly = true;
        if (sp != string::npos) {
            size_t sp2 = r.first_line.find(' ', sp+1);
            if (sp2 != string::npos) {
                string code = r.first_line.substr(sp+1, sp2 - sp - 1);
                r.status_code = atoi(code.c_str());
            }
        }
    } else {
        // not HTTP at all — responded with raw bytes
        r.version_anomaly = true;
    }
    // Server: header
    size_t sh = body.find("\nServer:");
    if (sh == string::npos) sh = body.find("\nserver:");
    if (sh != string::npos) {
        size_t se = body.find('\n', sh + 1);
        string sv = body.substr(sh + 8, (se == string::npos ? body.size() : se) - (sh + 8));
        r.server_hdr = trim(sv);
    } else {
        r.no_server_hdr = (r.status_code > 0);  // HTTP-ish but no Server:
    }
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
    // v2.3 — brand impersonation detection
    string brand_claimed;            // brand domain the cert vouches for
    bool   cert_impersonation = false; // brand cert served AND base_sni is not
                                       // a brand-owned name AND we'll check ASN
                                       // ownership at verdict time
    bool   passthrough_mode = false;   // Reality with real passthrough to `dest=`:
                                       // base (SNI-less) cert is for a famous
                                       // brand, yet per-SNI probes see different
                                       // certs — because the TLS stream is
                                       // transparently tunnelled to the real
                                       // brand, which then does its own SNI
                                       // routing. Classic stealth-optimised
                                       // Reality config.
    int    distinct_certs = 0;         // number of distinct cert SHAs observed
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
    // v2.3 — expanded probe list: common "dest=" targets for Xray/VLESS+Reality
    // setups (amazon/apple/microsoft/google etc.) + unrelated SNIs + a junk SNI.
    // This catches both "cert steering to dest" (Reality) and "cert statically
    // impersonates a famous brand" (Reality-static).
    static const vector<string> alt = {
        "www.microsoft.com",        // classic default dest
        "www.apple.com",             // common dest
        "www.amazon.com",            // common dest
        "www.google.com",            // common dest
        "www.cloudflare.com",        // common dest
        "www.bing.com",              // common dest
        "addons.mozilla.org",        // non-brand foreign SNI
        "www.yandex.ru",             // RU-side foreign SNI
        "www.github.com",            // common dest
        "random-domain-that-does-not-exist.invalid"  // junk — catches
                                                      // "always-accept-any-SNI"
                                                      // plain servers
    };
    int same = 0, total = 0;
    set<string> distinct;
    if (!base.cert_sha256.empty()) distinct.insert(base.cert_sha256);
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
            if (!p.cert_sha256.empty()) distinct.insert(p.cert_sha256);
        }
        c.entries.push_back(std::move(e));
    }
    c.distinct_certs = (int)distinct.size();

    // Brand-claim ALWAYS runs on the base cert. A famous-brand CN on the
    // origin's default SNI response is by itself the Reality-static
    // signature, regardless of how per-SNI variation looks — the ASN
    // cross-check at verdict time decides whether it's impersonation or
    // a legitimate brand endpoint.
    c.brand_claimed = cert_claims_brand(base.subject_cn, base.san);

    if (total >= 3 && same == total) {
        c.same_cert_always = true;
        // Reality discriminator — covers 3 cases:
        //   (A) Classical Reality: cert doesn't cover base_sni but covers
        //       one of the probed foreign SNIs (steering to dest=).
        //   (B) Reality-static / "pinned-brand" Reality: cert covers a
        //       famous brand domain (from BRAND_TABLE) even though we
        //       never sent that SNI as base. This is the Xray "fixed
        //       dest" profile where the cert from dest= is shown to
        //       every handshake.
        //   (C) Plain server with one default cert: cert covers nothing
        //       we asked about — neither base nor any foreign SNI.
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
        if (!c.brand_claimed.empty()) {
            // cert_impersonation flag is lit here, ASN cross-check
            // happens at verdict time where we have GeoIP data.
            c.cert_impersonation = true;
            // If we didn't catch Reality via foreign-SNI match but the
            // cert is for a brand, escalate to reality_like so the
            // verdict engine treats it as Reality.
            if (!c.reality_like && !cert_covers_base) {
                c.reality_like = true;
                c.matched_foreign_sni = c.brand_claimed;
            }
        }
        if (!c.reality_like) c.default_cert_only = true;
    } else if (total >= 3 && same == 0 && c.distinct_certs >= 3) {
        // Cert varies per SNI. If the base (SNI-less) cert is for a
        // famous brand on a non-owning ASN, this is Reality in full
        // passthrough-dest mode — the TLS stream is transparently
        // tunnelled to the real brand, and the real brand does its own
        // SNI-based vhost routing, which is why we see different certs
        // for different SNIs. The giveaway is that the BASE probe (no
        // SNI / host's own name) still returns a cert for a brand the
        // IP's ASN doesn't own.
        if (!c.brand_claimed.empty()) {
            c.cert_impersonation = true;
            c.reality_like = true;
            c.matched_foreign_sni = c.brand_claimed;
            c.passthrough_mode   = true;
        }
        // Otherwise it's real multi-tenant TLS — no hard signal.
    } else if (total >= 3 && same > 0 && same < total) {
        // Mixed: some SNIs share a cert, others get different ones.
        // Could be a dual-stack (Reality + real vhost) host, or Reality
        // with partial passthrough. Still a brand-on-non-owner-ASN is
        // the key signal.
        if (!c.brand_claimed.empty()) {
            c.cert_impersonation = true;
            // Mark as Reality-like: mixed cert behaviour with a brand
            // cert on base is nearly always Reality (a real vhost with
            // a brand cert would pass the "same_cert_always" test).
            c.reality_like = true;
            c.matched_foreign_sni = c.brand_claimed;
            c.passthrough_mode   = true;
        }
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
    // 2) HTTP GET /  — use the REAL host as the Host: header so a real
    //    web server (nginx/Apache/Caddy/CDN) can route properly and emit
    //    a legitimate 200/301/404. Xray/Trojan fallbacks can't route, so
    //    they emit the same canned reply as to junk probes.
    {
        string req = "GET / HTTP/1.1\r\nHost: " + host + "\r\nUser-Agent: curl/8.4.0\r\nAccept: */*\r\n\r\n";
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
// J3 response analysis  (v2.3)
//
// TSPU/GFW care about what the endpoint DOES with malformed input, not
// just whether it replies. We bucket replies as:
//   * real HTTP 4xx/5xx (normal web server behaviour)
//   * canned-fallback (same bytes / same first-line for different probes,
//     classic Xray `fallback+redirect` signature)
//   * non-HTTP reply (raw framed bytes — stream-layer proxy talking
//     protocol-of-its-own)
//   * invalid HTTP version in the reply line (e.g. "HTTP/0.0 307")
//   * pure silence (also normal for a strict TLS endpoint, kept here as
//     data rather than a verdict)
// ============================================================================
struct J3Analysis {
    int  silent = 0;
    int  resp   = 0;
    int  http_real = 0;        // replies start with HTTP/1.x or HTTP/2 and
                               // carry a sane status code
    int  http_bad_version = 0; // replies start with HTTP/ but with a
                               // nonsense version (HTTP/0.0, HTTP/3.X text,
                               // truncated "HTTP/"...)
    int  raw_non_http = 0;     // responded, not HTTP-shaped (stream proxy
                               // framing)
    int  canned_identical = 0; // number of probes sharing first_line+bytes
                               // with at least one OTHER probe
    string canned_line;        // the canned first line that repeated
    int  canned_bytes = 0;
};

static bool looks_like_http_line(const string& first_line, bool* bad_version_out = nullptr) {
    if (first_line.size() < 9) return false;
    if (first_line.compare(0, 5, "HTTP/") != 0) return false;
    // version is 3 chars after "HTTP/", e.g. "1.1"
    char x = first_line[5];
    char dot = first_line.size() > 6 ? first_line[6] : 0;
    char y = first_line.size() > 7 ? first_line[7] : 0;
    if (dot != '.') return false;
    // x must be 1 or 2; y must be 0 or 1 (for HTTP/1.0/1.1/2.0)
    bool good_version = ((x=='1' && (y=='0' || y=='1')) || (x=='2' && y=='0'));
    if (!good_version && bad_version_out) *bad_version_out = true;
    return true;
}

static J3Analysis j3_analyze(const vector<J3Result>& probes) {
    J3Analysis a;
    // Count canned pairs: same first_line AND same byte count -> canned
    // response regardless of what we sent.
    //
    // v2.3 refinement: a real web server returns the same HTTP 400 body
    // to every MALFORMED probe — that's normal nginx behaviour, not a
    // canned fallback. The Xray/Trojan tell is when a VALID HTTP probe
    // (our "HTTP GET /" and/or "HTTP abs-URI (proxy-style)") also gets
    // the same canned reply. We therefore only raise `canned_identical`
    // when at least one valid-HTTP probe shares the reply.
    struct KeyEntry { string line; int bytes; const char* name; };
    vector<KeyEntry> keys;
    for (auto& p: probes) {
        if (p.responded) {
            ++a.resp;
            keys.push_back({p.first_line, p.bytes, p.name.c_str()});
            bool bad_v = false;
            bool is_http = looks_like_http_line(p.first_line, &bad_v);
            if (is_http && !bad_v) ++a.http_real;
            else if (is_http && bad_v) ++a.http_bad_version;
            else                       ++a.raw_non_http;
        } else {
            ++a.silent;
        }
    }
    // A probe name is "valid-HTTP" if it sent a well-formed HTTP request
    // that a real web server would distinguish from junk.
    auto is_valid_http_probe = [](const char* n) {
        if (!n) return false;
        return strstr(n, "HTTP GET /") != nullptr ||
               strstr(n, "HTTP abs-URI") != nullptr;
    };
    // Find canned clusters: line+bytes appearing >=2 times AND including
    // at least one valid-HTTP probe (otherwise it's just uniform 400 on
    // malformed junk, which is the correct nginx behaviour).
    for (size_t i=0; i<keys.size(); ++i) {
        int count = 0;
        bool has_valid_http = false;
        for (size_t j=0; j<keys.size(); ++j) {
            if (keys[i].line == keys[j].line && keys[i].bytes == keys[j].bytes) {
                ++count;
                if (is_valid_http_probe(keys[j].name)) has_valid_http = true;
            }
        }
        if (count >= 2 && keys[i].line.size() > 3 && has_valid_http) {
            a.canned_identical = count;
            a.canned_line      = keys[i].line;
            a.canned_bytes     = keys[i].bytes;
            break;
        }
    }
    return a;
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
    struct PortFp {
        int port;
        FpResult fp;
        optional<TlsProbe>        tls;
        optional<SniConsistency>  sni;
        vector<J3Result>          j3;
        optional<J3Analysis>      j3a;   // v2.3 — J3 response analysis
        optional<HttpsProbe>      https; // v2.3 — active HTTP-over-TLS probe
    };
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

    // 2) GeoIP — 3 EU + 3 RU + 3 global providers, all in parallel.
    //    Diversity matters: EU and RU providers often disagree on hosting/
    //    VPN flags and the disagreement itself is diagnostic.
    printf("\n%s[2/7] GeoIP%s  (9 providers in parallel: 3 EU / 3 RU / 3 global)\n",
           col(C::BOLD), col(C::RST));
    auto fg_eu1 = std::async(std::launch::async, geo_ipapi_is,   R.dns.primary_ip); // EU (Latvia)
    auto fg_eu2 = std::async(std::launch::async, geo_iplocate,   R.dns.primary_ip); // EU (NL)
    auto fg_eu3 = std::async(std::launch::async, geo_freeipapi,  R.dns.primary_ip); // EU
    auto fg_ru1 = std::async(std::launch::async, geo_2ip_ru,     R.dns.primary_ip); // RU
    auto fg_ru2 = std::async(std::launch::async, geo_ipapi_ru,   R.dns.primary_ip); // RU (ip-api.com/ru)
    auto fg_ru3 = std::async(std::launch::async, geo_sypex,      R.dns.primary_ip); // RU (sypexgeo)
    auto fg_gl1 = std::async(std::launch::async, geo_ip_api_com, R.dns.primary_ip); // global
    auto fg_gl2 = std::async(std::launch::async, geo_ipwho_is,   R.dns.primary_ip); // global
    auto fg_gl3 = std::async(std::launch::async, geo_ipinfo_io,  R.dns.primary_ip); // global
    R.geos.push_back(fg_eu1.get()); R.geos.push_back(fg_eu2.get()); R.geos.push_back(fg_eu3.get());
    R.geos.push_back(fg_ru1.get()); R.geos.push_back(fg_ru2.get()); R.geos.push_back(fg_ru3.get());
    R.geos.push_back(fg_gl1.get()); R.geos.push_back(fg_gl2.get()); R.geos.push_back(fg_gl3.get());
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
                char agebuf[96] = {0};
                snprintf(agebuf, sizeof(agebuf), "age=%dd left=%dd",
                         tp.age_days, tp.days_left);
                f.details = tp.version + " / " + tp.cipher + " / ALPN=" +
                            (tp.alpn.empty()?"-":tp.alpn) + " / " + tp.group +
                            " / " + std::to_string(tp.handshake_ms) + "ms" +
                            "\n                       cert CN=" +
                            (tp.subject_cn.empty() ? "(none)" : tp.subject_cn) +
                            "  issuer=" + (tp.issuer_cn.empty() ? "(none)" : tp.issuer_cn) +
                            "  " + agebuf +
                            "  SAN=" + std::to_string(tp.san_count) +
                            (tp.is_wildcard  ? " wildcard" : "") +
                            (tp.self_signed  ? " self-signed" : "") +
                            (tp.is_letsencrypt ? " [free-CA]" : "");
                line(f);
                pf.tls = tp;
                // SNI consistency
                SniConsistency sc = sni_consistency(R.dns.primary_ip, o.port, R.dns.host);
                pf.sni = sc;
                if (sc.reality_like && sc.passthrough_mode) {
                    printf("        %sSNI behaviour: cert varies per SNI BUT base cert is for brand '%s' — Reality with real passthrough to dest= (stealth-optimised)%s\n",
                           col(C::RED), sc.matched_foreign_sni.c_str(), col(C::RST));
                } else if (sc.reality_like) {
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
                // v2.3 — active HTTP-over-TLS probe: what does the origin
                // actually emit as an HTTP reply? Real nginx → 'HTTP/1.1 200
                // ...\r\nServer: nginx'. Xray fallback → 'HTTP/0.0 307 ...'
                // or empty. Trojan → TLS handshake ok but HTTP returns
                // nothing or the dest='s real page (detectable).
                HttpsProbe hp = https_probe(R.dns.primary_ip, o.port, R.dns.host);
                pf.https = hp;
                if (hp.tls_ok) {
                    if (hp.responded) {
                        printf("        %sHTTP-over-TLS:%s %s%s%s",
                               col(C::DIM), col(C::RST),
                               hp.version_anomaly ? col(C::RED) :
                                 (hp.status_code>=200 && hp.status_code<600 ? col(C::GRN) : col(C::YEL)),
                               printable_prefix(hp.first_line, 70).c_str(),
                               col(C::RST));
                        if (!hp.server_hdr.empty())
                            printf("   Server: %s%s%s",
                                   col(C::CYN),
                                   printable_prefix(hp.server_hdr, 40).c_str(),
                                   col(C::RST));
                        else if (hp.status_code > 0)
                            printf("   %s(no Server header)%s",
                                   col(C::YEL), col(C::RST));
                        if (hp.version_anomaly)
                            printf("   %s[!version anomaly]%s",
                                   col(C::RED), col(C::RST));
                        printf("\n");
                    } else {
                        printf("        %sHTTP-over-TLS: no reply (TLS ok, origin silent on HTTP request) — stream-layer proxy signature%s\n",
                               col(C::RED), col(C::RST));
                    }
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
        // v2.3 — compute + cache J3 analysis (canned responses, HTTP-version
        // anomalies, raw-non-HTTP replies) so the verdict engine can use it.
        J3Analysis ja = j3_analyze(probes);
        // attach
        for (auto& pf: R.fps) if (pf.port == o.port) {
            pf.j3  = std::move(probes);
            pf.j3a = ja;
            break;
        }
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
        // v2.3 — J3 deep-analysis summary printed inline so the user SEES
        // the reasoning instead of waiting for the verdict block.
        //   On TLS ports, a canned 400 to raw-TCP probes is normal nginx
        //   behaviour; only escalate if the HTTP-over-TLS probe ALSO showed
        //   anomaly. See matching gate in the verdict engine.
        bool inline_is_tls = false, inline_https_anomaly = false;
        for (auto& pf: R.fps) if (pf.port == o.port) {
            inline_is_tls = (pf.tls && pf.tls->ok);
            if (pf.https && pf.https->tls_ok &&
                (!pf.https->responded || pf.https->version_anomaly ||
                 (pf.https->responded && pf.https->server_hdr.empty())))
                inline_https_anomaly = true;
            break;
        }
        bool inline_canned_hard = (ja.canned_identical >= 2) &&
                                  (!inline_is_tls || inline_https_anomaly);
        if (inline_canned_hard) {
            printf("     %s!! canned response:%s the SAME first-line (%dB '%s') came back for %d different probes — not a real web server, that's a static fallback page (classic Xray `fallback+redirect`, Trojan, or Caddy placeholder)\n",
                   col(C::RED), col(C::RST),
                   ja.canned_bytes,
                   printable_prefix(ja.canned_line, 50).c_str(),
                   ja.canned_identical);
        } else if (ja.canned_identical >= 2 && inline_is_tls) {
            printf("     %suniform reply:%s the SAME first-line (%dB '%s') for %d raw-TCP probes, but the HTTP-over-TLS probe is clean — that's normal nginx/CDN behaviour on a TLS port (not a fallback)\n",
                   col(C::DIM), col(C::RST),
                   ja.canned_bytes,
                   printable_prefix(ja.canned_line, 50).c_str(),
                   ja.canned_identical);
        }
        if (ja.http_bad_version > 0) {
            printf("     %s!! HTTP version anomaly:%s %d probe(s) came back with an invalid HTTP version string (e.g. HTTP/0.0) — signature of a stream-proxy's fallback/redirect code path, not of nginx/Apache/Caddy\n",
                   col(C::RED), col(C::RST), ja.http_bad_version);
        }
        if (ja.raw_non_http > 0 && ja.http_real == 0) {
            printf("     %s!! raw non-HTTP bytes:%s %d probe(s) got binary replies instead of HTTP — origin is speaking its own framing (Shadowsocks, Trojan, custom proxy)\n",
                   col(C::YEL), col(C::RST), ja.raw_non_http);
        }
    }

    // 7) Verdict engine (v2.3 — deep-audit model)
    //
    // v2.3 adds ACTIVE on-the-wire signals that are extremely expensive for
    // a legit web origin to fake but trivially show up in any Xray/Trojan/
    // Reality deployment:
    //
    //   * Cert impersonation — famous-brand CN (amazon/microsoft/apple/...)
    //     on an ASN that has no commercial relationship with that brand.
    //     This is the Reality "static dest" profile (dest=www.amazon.com:443)
    //     and it's a hard signal because the only way a random VPS in LV on
    //     AS42532 serves a valid Amazon cert is by proxying the TLS
    //     handshake to the real amazon.com.
    //
    //   * Short-validity cert — total_validity_days < 14 is never normal.
    //     Let's Encrypt issues 90d certs, commercial CAs 30-365d. A cert
    //     with 6 days of total lifetime is either LE staging (not used by
    //     real sites), manually generated for a proxy, or chain rot.
    //
    //   * Canned-response fallback — if two or more J3 probes get back
    //     EXACTLY the same first-line + byte count, the origin isn't a
    //     real web server, it's a stream-proxy handing out a static
    //     fallback page on every mismatch. Xray's `fallback+redirect`
    //     famously emits "HTTP/0.0 307 Temporary Redirect".
    //
    //   * HTTP-version anomaly — a response line of HTTP/0.X or HTTP/3.X
    //     (text) etc. never comes out of nginx/Apache/Caddy; it's a
    //     proxy-specific serialiser.
    //
    //   * 3x-ui / x-ui port cluster — panel installers use a stock set of
    //     Cloudflare-proxy-friendly TLS ports (2053 / 2083 / 2087 / 2096 /
    //     8443 / 8880). Two or more of these on one IP is a panel-install
    //     signature.
    //
    //   * HTTP-over-TLS response audit — after a clean TLS handshake we
    //     actually speak HTTP/1.1 and look for a real Server: header.
    //     No Server: header AND HTTP version anomaly AND/or empty response
    //     = stream-layer proxy.
    //
    // Calibration: hosting-ASN, single :443, IKE control ports,
    // single-source GeoIP tags, KEX != X25519 etc. stay informational
    // with hardening advice (not a penalty on their own).
    // ------------------------------------------------------------------
    printf("\n%s[7/7] Verdict%s\n", col(C::BOLD), col(C::RST));
    int score = 100;
    vector<string> signals_major;  // hard evidence: named VPN, open
                                   // proxy, multi-source tag, Tor, etc.
    vector<string> signals_minor;  // soft evidence: fresh cert in combo,
                                   // self-signed, TLS<1.3, Reality, etc.
    vector<std::pair<string,string>> notes;   // (tag, observation)  — no penalty
    vector<std::pair<string,string>> hardening; // (tag, advice)
    vector<std::pair<int,string>>    port_roles; // (port, role label)
    vector<std::pair<string,string>> dpi_axes;   // (axis, exposure)
    bool xray_reality_primary = false, xray_reality_hidden = false;
    int  reality_port_count   = 0;

    auto flag_minor = [&](const string& s, int penalty = 3) {
        signals_minor.push_back(s);
        score -= penalty;
    };
    auto flag_major = [&](const string& s, int penalty) {
        signals_major.push_back(s);
        score -= penalty;
    };
    auto note = [&](const string& tag, const string& s) {
        notes.push_back({tag, s});
    };

    // ---- GeoIP signals ---------------------------------------------
    // v2.3: hosting-ASN and single-source VPN tags are informational only.
    int vpn_hits = 0, proxy_hits = 0, hosting_hits = 0, tor_hits = 0;
    for (auto& g: R.geos) {
        if (g.is_hosting) ++hosting_hits;
        if (g.is_vpn)     ++vpn_hits;
        if (g.is_proxy)   ++proxy_hits;
        if (g.is_tor)     ++tor_hits;
    }
    int gprov = (int)R.geos.size();
    if (tor_hits)
        flag_major("flagged as Tor exit by " + std::to_string(tor_hits) + " GeoIP source(s)", 25);
    if (vpn_hits >= 2)
        flag_major("flagged as VPN by " + std::to_string(vpn_hits) + " GeoIP sources (multi-source consensus)", 18);
    else if (vpn_hits == 1)
        note("geo-vpn", "1 of " + std::to_string(gprov) + " GeoIP sources tagged this IP as VPN (single-source — likely a false positive)");
    if (proxy_hits >= 2)
        flag_major("flagged as proxy by " + std::to_string(proxy_hits) + " GeoIP sources (multi-source consensus)", 12);
    else if (proxy_hits == 1)
        note("geo-proxy", "1 of " + std::to_string(gprov) + " GeoIP sources tagged this IP as proxy (single-source — likely a false positive)");
    if (hosting_hits >= 1)
        note("asn-hosting", std::to_string(hosting_hits) + " of " + std::to_string(gprov) + " sources classify the ASN as hosting/datacenter "
             "(normal for any public server — not a red flag on its own)");
    if (R.geos.size() >= 2 && !R.geos[0].country_code.empty() && !R.geos[1].country_code.empty()
        && R.geos[0].country_code != R.geos[1].country_code)
        note("geo-cc-mismatch", "GeoIP country codes disagree between providers (normal GeoIP noise)");

    // ---- TCP exposure signals --------------------------------------
    // v2.3: only truly VPN/proxy-specific ports carry a penalty.
    // "Only :443 open" / "SSH/22 open" are NORMAL for a public web host —
    // moved to Informational with a Hardening entry.
    set<int> openset;
    for (auto& o: R.open_tcp) openset.insert(o.port);
    if (openset.count(3389)) flag_major("RDP/3389 reachable from Internet (attack surface, not VPN-specific)", 10);
    if (openset.count(1080) || openset.count(1081))
        flag_major("SOCKS5 exposed without wrapper (proxy signature)", 15);
    if (openset.count(3128) || openset.count(8118))
        flag_major("HTTP proxy exposed without wrapper", 12);
    if (openset.count(1194))
        flag_major("OpenVPN TCP/1194 default port open (hard protocol signature)", 15);
    if (openset.count(8388) || openset.count(8488))
        flag_major("Shadowsocks default port exposed (instantly fingerprintable)", 15);
    if (openset.count(10808) || openset.count(10809) || openset.count(10810))
        flag_major("v2ray/xray local-style inbound port exposed to WAN (misconfig)", 12);
    // Informational — not red flags, but we surface actionable hardening:
    if (openset.count(22))
        note("ssh-22", "SSH/22 open with a standard banner — visible on Shodan/ASN-sweeps as 'server host', not as VPN");
    if (openset.count(500) || openset.count(4500))
        note("ike-ports", "IKE control ports (500/4500) open — normal for any IPsec-capable router");
    if (openset.count(443) && R.open_tcp.size() == 1)
        note("single-443", "only :443 is reachable — indistinguishable from a typical reverse-proxy / corporate single-service host, but provides no web 'context' (no :80 redirect, no decoy services)");
    else if (openset.count(443) && R.open_tcp.size() <= 3 && hosting_hits)
        note("sparse-ports", std::to_string(R.open_tcp.size()) + " TCP ports open on a hosting ASN with :443 — sparse profile; common for both minimal corporate servers and single-purpose proxy VPSes");

    // ---- UDP handshake signals -------------------------------------
    for (auto& [p,u]: R.udp_probes) {
        if (!u.responded) continue;
        if (p == 1194)  flag_major("OpenVPN UDP/1194 reflects HARD_RESET (protocol-level match)", 22);
        if (p == 500)   flag_minor("IKEv2 responder on UDP/500 (IPsec endpoint)", 5);
        if (p == 4500)  flag_minor("IKEv2 NAT-T responder on UDP/4500 (IPsec endpoint)", 5);
        if (p == 51820) flag_major("WireGuard UDP/51820 answers handshake (default port signature)", 15);
        if (p == 41641) flag_minor("Tailscale UDP/41641 answers handshake (default port)", 5);
    }

    // ---- 3x-ui / x-ui / panel-installer port-cluster signature (v2.3) ---
    //   Cloudflare proxy-friendly TLS ports 2053/2083/2087/2096/8443/8880
    //   are what 3x-ui/x-ui/V2bX/Marzban panels suggest by default. Two or
    //   more of them open together on one IP is an installer fingerprint
    //   that regular webhosts do not produce.
    int xui_cluster_hits = 0;
    vector<int> xui_open;
    for (int p: {2053, 2083, 2087, 2096, 8443, 8880, 6443, 7443, 9443}) {
        if (openset.count(p)) { ++xui_cluster_hits; xui_open.push_back(p); }
    }
    bool xui_cluster_seen = false;
    if (xui_cluster_hits >= 2) {
        string portstr;
        for (size_t i=0;i<xui_open.size();++i) {
            if (i) portstr += ",";
            portstr += std::to_string(xui_open[i]);
        }
        flag_major(std::to_string(xui_cluster_hits) + " of the classical 3x-ui/x-ui/Marzban panel TLS ports are open ({" + portstr + "}) — installer fingerprint; regular webhosts rarely open this exact set", 14);
        xui_cluster_seen = true;
    } else if (xui_cluster_hits == 1) {
        note("xui-single-port", "one panel-installer TLS port open (:" + std::to_string(xui_open[0]) +
             ") — ambiguous by itself, but these ports are strongly associated with 3x-ui/x-ui proxy panels");
    }

    // ---- Silent-high-port + TLS elsewhere (v2.3 multipath detector) -----
    //   A classic Xray multi-inbound setup exposes :443 (TLS-fronted VLESS)
    //   AND a silent high port (direct VLESS/Trojan listener). That high
    //   port accepts TCP, says nothing on connect, doesn't speak TLS, and
    //   dies on any junk.  Real business services don't look like that.
    int silent_high_ports = 0;
    for (auto& o: R.open_tcp) {
        if (o.port >= 10000 && o.banner.empty()) ++silent_high_ports;
    }
    bool tls_on_443 = openset.count(443) > 0;
    if (tls_on_443 && silent_high_ports >= 1 && R.open_tcp.size() <= 6) {
        flag_minor(std::to_string(silent_high_ports) + " silent high-port(s) open alongside :443 TLS on a sparse host — classic multi-inbound proxy layout (Xray VLESS :443 + direct listener on high port)", 7);
    }

    // ---- TLS posture + cert red flags (v2.3 — adds impersonation/short-validity)
    //   * TLS<1.3 is still a weak-posture penalty (real 2026 sites are TLS1.3).
    //   * ALPN != h2 and KEX != X25519 → informational only, not a penalty.
    //   * Fresh cert <14d → penalty ONLY if the host also has (sparse-ports
    //     profile AND hosting ASN). An isolated fresh LE cert on a
    //     multi-port corporate host is just normal LE rotation.
    //   * Self-signed, expired, zero-SAN — still red flags (not normal).
    //   * total_validity_days < 14 — HARD flag (no legit CA issues <14d).
    //   * brand cert on non-brand ASN — HARD flag (Reality-static profile).
    bool any_tls = false, any_reality = false;
    bool any_impersonation = false;
    int  cert_issuers_seen_free_ca = 0;
    int  cert_fresh_ports = 0;
    int  cert_self_signed_ports = 0;
    int  cert_short_validity_ports = 0;
    int  cert_impersonation_ports = 0;
    int  tls_not_13_ports = 0;
    int  alpn_not_h2_ports = 0;
    int  group_not_x25519_ports = 0;
    bool sparse_vps_profile = (openset.count(443) && R.open_tcp.size() <= 3 && hosting_hits > 0);

    // collect all ASN-org strings across providers for brand cross-check
    vector<string> asn_orgs_all;
    for (auto& g: R.geos) if (!g.asn_org.empty()) asn_orgs_all.push_back(g.asn_org);
    for (auto& pf: R.fps) {
        if (pf.tls && pf.tls->ok) {
            any_tls = true;
            if (pf.tls->version != "TLSv1.3") {
                flag_minor("TLS < 1.3 on :" + std::to_string(pf.port) +
                           " (" + pf.tls->version + ") — weak handshake posture, modern clients expect TLS 1.3", 4);
                ++tls_not_13_ports;
            }
            if (pf.tls->alpn != "h2") {
                note("alpn", "ALPN on :" + std::to_string(pf.port) + " = '" +
                     (pf.tls->alpn.empty() ? "-" : pf.tls->alpn) +
                     "' (HTTP/1.1-only is still normal for many corporate apps; h2 is not mandatory)");
                ++alpn_not_h2_ports;
            }
            if (!pf.tls->group.empty() && pf.tls->group != "X25519") {
                note("kex", "KEX group on :" + std::to_string(pf.port) + " = '" + pf.tls->group +
                     "' (X25519 is preferred by modern browsers but ECDHE-P256 is perfectly valid)");
                ++group_not_x25519_ports;
            }
            if (pf.tls->age_days > 0 && pf.tls->age_days < 14) {
                ++cert_fresh_ports;
                if (sparse_vps_profile) {
                    flag_minor("cert on :" + std::to_string(pf.port) +
                               " is fresh (" + std::to_string(pf.tls->age_days) +
                               "d) AND open-port profile is sparse on hosting ASN — classic 'new VLESS host' fingerprint",
                               6);
                } else {
                    note("cert-fresh", "cert on :" + std::to_string(pf.port) + " is " +
                         std::to_string(pf.tls->age_days) + "d old (fresh LE certs are normal for any site rotating every 60-90d)");
                }
            }
            if (pf.tls->self_signed) {
                flag_major("self-signed cert on :" + std::to_string(pf.port) +
                           " (subject==issuer) — browsers would reject; typical of Shadowsocks/Trojan/test setups", 10);
                ++cert_self_signed_ports;
            }
            if (pf.tls->is_letsencrypt) {
                ++cert_issuers_seen_free_ca;
                // Not a signal — LE / ZeroSSL / GTS are the norm for public sites.
            }
            if (pf.tls->days_left < 0) {
                flag_minor("cert on :" + std::to_string(pf.port) +
                           " EXPIRED " + std::to_string(-pf.tls->days_left) +
                           "d ago — no legit site runs an expired cert; abandonment or misconfig signal", 8);
            }
            if (pf.tls->san_count == 0 && !pf.tls->subject_cn.empty()) {
                note("no-san", "cert on :" + std::to_string(pf.port) +
                     " has no SAN entries (only legacy CN) — unusual for modern public TLS, but some internal certs do this");
            }
            // v2.3 — short-validity cert: total lifetime < 14d is never
            // issued by real CAs to production sites. LE = 90d, commercial
            // = 30-365d. 5-14d means manually-generated internal cert or
            // LE staging, used by Xray/Trojan quickfire setups.
            if (pf.tls->total_validity_days > 0 && pf.tls->total_validity_days < 14) {
                flag_major("cert on :" + std::to_string(pf.port) +
                           " has a total validity of only " + std::to_string(pf.tls->total_validity_days) +
                           " days (notBefore→notAfter) — no public CA issues <14d certs to real sites; this is a hand-rolled internal cert or LE staging, a hard signal of a proxy/test setup",
                           15);
                ++cert_short_validity_ports;
            }
        }
        // v2.3 — brand impersonation check:
        // If the cert vouches for a famous brand but the ASN clearly has
        // nothing to do with that brand, this is Reality-static / cert
        // cloning. This is a HARD signal (the only reason a random VPS in
        // US on AS56971 serves a valid Amazon cert is because it's
        // proxying the handshake).
        if (pf.sni && pf.sni->cert_impersonation && !pf.sni->brand_claimed.empty()) {
            bool owns = asn_owns_brand(pf.sni->brand_claimed, asn_orgs_all);
            if (!owns) {
                flag_major("cert on :" + std::to_string(pf.port) +
                           " vouches for brand '" + pf.sni->brand_claimed +
                           "' but the ASN is not owned by that brand — Reality-static / "
                           "cert-cloning signature (Xray `dest=" + pf.sni->brand_claimed + "` profile)",
                           22);
                ++cert_impersonation_ports;
                any_impersonation = true;
            } else {
                // legit brand on legit ASN — no signal
                note("brand-legit", "cert on :" + std::to_string(pf.port) +
                     " is for '" + pf.sni->brand_claimed + "' and the ASN does match that brand — legitimate brand endpoint");
            }
        }
        if (pf.sni && pf.sni->reality_like) {
            any_reality = true;
            ++reality_port_count;
            // Reality IS identifiable — the very fact we can recognise it
            // as Reality means a DPI engine can too.
            if (pf.sni->passthrough_mode) {
                flag_major("Reality in passthrough mode on :" + std::to_string(pf.port) +
                           " (base cert is for '" + pf.sni->matched_foreign_sni +
                           "' — stream tunnelled to the real brand, SNI-based vhost routing "
                           "then returns different certs per SNI; cert + ASN disagree)", 14);
            } else {
                flag_major("Reality cert-steering pattern on :" + std::to_string(pf.port) +
                           " (cert covers foreign SNI '" + pf.sni->matched_foreign_sni + "')", 12);
            }
        }
        // v2.3 — Server-header brand impersonation. CloudFront / AmazonS3 /
        // gws / Microsoft-IIS / Yandex banners are only served by the real
        // brand's infrastructure. If the IP we're hitting answers with one
        // of those but the ASN doesn't own the brand — the box is proxying
        // the HTTP stream to the real brand (Reality passthrough). This
        // doubles as an independent confirmation of cert impersonation, but
        // fires even when the TLS-cert check missed it (e.g. brand not in
        // SAN but server-banner still leaks through).
        if (pf.https && pf.https->tls_ok && pf.https->responded &&
            !pf.https->server_hdr.empty()) {
            string sbr = server_header_brand(pf.https->server_hdr);
            if (!sbr.empty()) {
                bool owns = asn_owns_brand(sbr, asn_orgs_all);
                if (!owns) {
                    flag_major("HTTP-over-TLS on :" + std::to_string(pf.port) +
                               " returns `Server: " + printable_prefix(pf.https->server_hdr, 40) +
                               "` — that banner is only emitted by '" + sbr +
                               "' infrastructure, yet the ASN isn't owned by that brand "
                               "(origin is proxying the HTTP stream to the real brand = Reality passthrough)",
                               18);
                    // Also count this toward the cert-impersonation side if the
                    // TLS-cert check didn't catch the same brand already.
                    if (!(pf.sni && pf.sni->cert_impersonation)) {
                        ++cert_impersonation_ports;
                        any_impersonation = true;
                    }
                }
            }
        }
        // v2.3 — Active HTTP-over-TLS probe verdicts.
        //   * version anomaly (HTTP/0.0 etc.) = hard fake-server signal
        //   * no Server: header AND responded = likely middleware/proxy
        //   * TLS ok but HTTP empty = stream-layer proxy
        if (pf.https && pf.https->tls_ok) {
            if (pf.https->version_anomaly && pf.https->responded) {
                flag_major("HTTP-over-TLS on :" + std::to_string(pf.port) +
                           " returned an invalid HTTP version ('" +
                           printable_prefix(pf.https->first_line, 40) +
                           "') — no real web server emits that; classic Xray/Trojan fallback signature",
                           14);
            }
            if (pf.https->responded && pf.https->server_hdr.empty() && !pf.https->version_anomaly) {
                flag_minor("HTTP-over-TLS on :" + std::to_string(pf.port) +
                           " responded without a Server: header — real nginx/Apache/Caddy/CDN set one; absence is a middleware tell",
                           5);
            }
            if (!pf.https->responded) {
                flag_minor("HTTP-over-TLS on :" + std::to_string(pf.port) +
                           " — TLS handshake succeeded but origin did not return any HTTP bytes to a valid GET / request. Legitimate web origins always reply (200/301/404/502). Silence here = stream-layer proxy.",
                           8);
            }
        }
    }

    // ---- J3 active-probe roles -------------------------------------
    // v2.3: re-add the "proxy in front of origin" detection.
    //   * nginx/Apache/Caddy return HTTP/1.1 400 Bad Request (or similar
    //     4xx) on non-TLS bytes hitting a TLS port. Most CDNs do too.
    //   * A host that does TLS 1.3 cleanly but silently eats every
    //     HTTP-junk probe is almost certainly running a stream-layer
    //     proxy (Xray/Reality/Trojan/SS-AEAD) that drops anything not
    //     matching its own framing. This is NOT Reality cert-steering
    //     (which would require the cert discriminator to fire), but it
    //     IS strong evidence of middleware between you and the origin.
    int j3_silent_total = 0, j3_resp_total = 0, j3_ports_checked = 0;
    int j3_canned_ports = 0, j3_badver_ports = 0, j3_raw_nonhttp_ports = 0;
    bool proxy_middleware_seen = false;
    for (auto& pf: R.fps) {
        if (pf.j3.size() < 6) continue;
        ++j3_ports_checked;
        int sil = 0, rsp = 0;
        // Also: among responses, count how many look like real HTTP (start with "HTTP/")
        int http_like_responses = 0;
        for (auto& j: pf.j3) {
            if (j.responded) {
                ++rsp;
                if (j.first_line.rfind("HTTP/", 0) == 0) ++http_like_responses;
            } else {
                ++sil;
            }
        }
        j3_silent_total += sil;
        j3_resp_total   += rsp;

        // v2.3 — tap the J3 analysis for canned/anomaly signals.
        //   * On TLS ports, the ACTIVE HTTP-over-TLS probe is the
        //     authoritative canned-fallback signal (post-TLS decode).
        //     Raw-TCP canned replies to a TLS port are legitimate nginx
        //     behaviour ("you sent non-TLS, here's 400"); we only escalate
        //     the raw-TCP canned on a TLS port if the HTTPS-over-TLS probe
        //     ALSO shows anomaly (empty/version-anomaly/no-Server).
        //   * On non-TLS ports, canned identical replies to different
        //     probes including valid HTTP GET / are hard Xray fallback.
        bool is_tls_port        = (pf.tls && pf.tls->ok);
        bool https_probe_anomaly =
            (pf.https && pf.https->tls_ok &&
             (!pf.https->responded ||
              pf.https->version_anomaly ||
              (pf.https->responded && pf.https->server_hdr.empty())));
        bool canned_real = (pf.j3a && pf.j3a->canned_identical >= 2) &&
                           (!is_tls_port || https_probe_anomaly);
        if (canned_real) {
            ++j3_canned_ports;
            flag_major("port :" + std::to_string(pf.port) +
                       " returns a canned fallback page (same first-line '" +
                       printable_prefix(pf.j3a->canned_line, 50) +
                       "' with identical byte count " + std::to_string(pf.j3a->canned_bytes) +
                       "B for " + std::to_string(pf.j3a->canned_identical) +
                       " different probes" +
                       (is_tls_port ? " AND the HTTP-over-TLS probe is also anomalous" : "") +
                       ") — real web servers vary their replies; this is the Xray/Trojan `fallback+redirect` signature",
                       18);
        }
        if (pf.j3a) {
            if (pf.j3a->http_bad_version >= 1) {
                ++j3_badver_ports;
                flag_major("port :" + std::to_string(pf.port) +
                           " emits an HTTP reply with an invalid version (e.g. HTTP/0.0) " +
                           std::to_string(pf.j3a->http_bad_version) +
                           " time(s) — nginx/Apache/Caddy never produce this; classic Xray fallback signature",
                           14);
            }
            if (pf.j3a->raw_non_http >= 2 && pf.j3a->http_real == 0) {
                ++j3_raw_nonhttp_ports;
                flag_minor("port :" + std::to_string(pf.port) +
                           " answers with raw non-HTTP bytes (" + std::to_string(pf.j3a->raw_non_http) +
                           " probes) — stream-layer proxy framing (Shadowsocks/Trojan/custom)", 7);
            }
        }

        bool has_reality = pf.sni && pf.sni->reality_like;
        bool tls_ok      = pf.tls && pf.tls->ok;
        bool tls_failed  = pf.tls && !pf.tls->ok;

        // per-port role string — now carries TLS + cert summary
        string role;
        if (has_reality && tls_ok) {
            if (sil >= 6) {
                role = "Reality hidden-mode (silent-on-junk — strong DPI signature)";
                xray_reality_hidden = true;
                score -= 3;
            } else if (rsp >= 4) {
                role = "Reality + HTTP fallback (mimics real web server on junk)";
                xray_reality_primary = true;
            } else {
                role = "Reality (TLS endpoint)";
            }
        } else if (tls_ok) {
            // *** proxy-middleware heuristic ***
            // TLS handshake clean, but junk probes are silently dropped:
            // a real web server (nginx/Apache/Caddy/CDN) would emit
            // HTTP/1.1 400 for non-TLS bytes. Silent = middleware.
            if (sil >= 6 && rsp == 0) {
                role = "TLS endpoint that silently drops all HTTP/junk — proxy/middleware in front of origin (Xray/Trojan/SS-AEAD — nginx/Apache would return HTTP 400)";
                flag_minor("port :" + std::to_string(pf.port) +
                           " does TLS 1.3 cleanly but silently drops every HTTP junk probe — "
                           "strong signature of a stream-layer proxy sitting in front of the origin "
                           "(Xray/Trojan/SS). Normal web servers reply with HTTP 400 on non-TLS bytes.",
                           7);
                proxy_middleware_seen = true;
            } else if (rsp >= 4 && http_like_responses == 0) {
                role = "TLS endpoint that answers junk with non-HTTP replies — atypical middleware (bytes come back but not in HTTP form)";
                flag_minor("port :" + std::to_string(pf.port) +
                           " answered " + std::to_string(rsp) +
                           " junk probes but none looked like HTTP — origin is not a standard web server "
                           "(possible custom proxy framing)", 5);
                proxy_middleware_seen = true;
            } else if (rsp >= 7) {
                role = "generic HTTPS / CDN origin (junk probes get HTTP 4xx as expected)";
            } else {
                role = "TLS endpoint (not Reality, mixed probe behaviour)";
            }
            // enrich with cert summary
            bool server_brand_mismatch = false;
            if (pf.https && pf.https->tls_ok && !pf.https->server_hdr.empty()) {
                string sb = server_header_brand(pf.https->server_hdr);
                if (!sb.empty() && !asn_owns_brand(sb, asn_orgs_all))
                    server_brand_mismatch = true;
            }
            char buf[512] = {0};
            snprintf(buf, sizeof(buf),
                     " — %s / ALPN=%s / CN=%s / issuer=%s / age=%dd / validity=%dd / SAN=%d%s%s%s%s",
                     pf.tls->version.c_str(),
                     pf.tls->alpn.empty() ? "-" : pf.tls->alpn.c_str(),
                     pf.tls->subject_cn.empty() ? "(none)" : pf.tls->subject_cn.c_str(),
                     pf.tls->issuer_cn.empty() ? "(none)" : pf.tls->issuer_cn.c_str(),
                     pf.tls->age_days, pf.tls->total_validity_days, pf.tls->san_count,
                     (pf.tls->total_validity_days > 0 && pf.tls->total_validity_days < 14) ? " [!short-validity]" : "",
                     (pf.sni && pf.sni->cert_impersonation) ? " [!brand-impersonation]" : "",
                     server_brand_mismatch ? " [!server-impersonation]" : "",
                     canned_real ? " [!canned-fallback]" : "");
            role += buf;
            // Upgrade the role label for the hard-signal cases: impersonation
            // and canned-fallback take precedence over the generic role.
            // canned_real already accounts for TLS-port vs HTTPS-probe-anomaly.
            bool role_upgraded = false;
            if (pf.sni && pf.sni->cert_impersonation && !pf.sni->brand_claimed.empty()) {
                bool owns = asn_owns_brand(pf.sni->brand_claimed, asn_orgs_all);
                if (!owns) {
                    const char* label = (pf.sni->passthrough_mode)
                        ? "Reality with real passthrough (cert tunnelled from '"
                        : "Reality-static / cert-cloning (cert impersonates '";
                    role = string(label) + pf.sni->brand_claimed +
                           (pf.sni->passthrough_mode
                              ? "' via `dest=` — TLS stream transparently tunnelled) "
                              : "' on an unrelated ASN) ") + role;
                    role_upgraded = true;
                }
            }
            // Independent channel: Server-header brand mismatch. Fires when
            // the cert-cert-cert check missed it but `Server: CloudFront/gws/...`
            // on a non-owner ASN still leaks the passthrough.
            if (!role_upgraded && pf.https && pf.https->tls_ok &&
                !pf.https->server_hdr.empty()) {
                string sb = server_header_brand(pf.https->server_hdr);
                if (!sb.empty() && !asn_owns_brand(sb, asn_orgs_all)) {
                    role = "Reality with real passthrough (`Server: " +
                           printable_prefix(pf.https->server_hdr, 24) +
                           "` banner comes from '" + sb +
                           "' infrastructure on non-owner ASN) " + role;
                    role_upgraded = true;
                }
            }
            if (!role_upgraded && canned_real) {
                role = "TLS endpoint emitting canned fallback response "
                       "(Xray/Trojan `fallback+redirect` page served for every probe) " + role;
            }
        } else if (tls_failed && sil >= 6) {
            role = "TLS handshake refused AND silent on HTTP — stream-layer proxy that only speaks its own framing (Shadowsocks-AEAD / Trojan / strict-mode Reality / custom SOCKS-over-TLS) OR a firewalled service";
            flag_minor("port :" + std::to_string(pf.port) +
                       " rejects TLS AND drops HTTP junk — likely a stream-proxy that only accepts its own framing "
                       "(SS-AEAD, Trojan, Reality-strict). Not conclusive: could also be a firewalled internal service.",
                       5);
        } else if (tls_failed) {
            role = "TLS handshake failed + mixed probes (ambiguous — internal service / non-TLS-on-TLS-port misconfig)";
        }
        if (!role.empty()) port_roles.push_back({pf.port, role});
    }

    // ---- SSH role classification -----------------------------------
    for (auto& o: R.open_tcp) {
        bool is_ssh_std  = (o.port==22 || o.port==2222 || o.port==22222);
        bool has_banner  = !o.banner.empty() && o.banner.rfind("SSH-",0)==0;
        if (is_ssh_std && has_banner)
            port_roles.push_back({o.port, "SSH (advertised banner, standard port) — '" +
                                          printable_prefix(o.banner, 40) + "'"});
        else if (has_banner && !is_ssh_std)
            port_roles.push_back({o.port, "SSH on non-standard port (banner still leaks version) — '" +
                                          printable_prefix(o.banner, 40) + "'"});
    }

    // ---- HTTP-only port roles --------------------------------------
    for (auto& pf: R.fps) {
        if (pf.fp.service == "HTTP" || pf.fp.service == "HTTP?") {
            port_roles.push_back({pf.port, "plain HTTP — " +
                                          (pf.fp.details.empty() ? "no banner" : printable_prefix(pf.fp.details, 90))});
        } else if (pf.fp.service == "HTTP-PROXY") {
            port_roles.push_back({pf.port, "OPEN HTTP PROXY (accepts CONNECT) — " +
                                          printable_prefix(pf.fp.details, 80)});
            flag_major("open HTTP proxy (accepts CONNECT) on :" + std::to_string(pf.port), 20);
        } else if (pf.fp.service == "SOCKS5") {
            port_roles.push_back({pf.port, "OPEN SOCKS5 — " +
                                          printable_prefix(pf.fp.details, 80)});
            flag_major("open SOCKS5 endpoint on :" + std::to_string(pf.port), 20);
        }
    }

    // v2.3: no blanket COMBO penalty — we already combined fresh-cert
    // with sparse-port+hosting above. Blanket combo on arbitrary minors
    // over-penalised any minimal VPS.
    score = std::max(0, std::min(100, score));
    R.score = score;
    if (score >= 85)      R.label = "CLEAN";
    else if (score >= 70) R.label = "NOISY";
    else if (score >= 50) R.label = "SUSPICIOUS";
    else                  R.label = "OBVIOUSLY-VPN";

    const char* color = score>=85?C::GRN : score>=70?C::YEL : score>=50?C::YEL : C::RED;

    // ---- Stack identification (strict, no guessing) ----------------
    string stack_name;
    bool any_wg = std::any_of(R.udp_probes.begin(), R.udp_probes.end(),
                              [](auto& x){return x.first==51820 && x.second.responded;});
    bool any_ovpn_udp = std::any_of(R.udp_probes.begin(), R.udp_probes.end(),
                                    [](auto& x){return x.first==1194 && x.second.responded;});
    bool any_canned    = (j3_canned_ports > 0);
    bool any_bad_ver   = (j3_badver_ports  > 0);
    bool any_short_val = (cert_short_validity_ports > 0);
    if (any_impersonation && xui_cluster_seen)
        stack_name = "Xray-core VLESS+Reality on a 3x-ui/x-ui/Marzban panel install "
                     "(cert impersonates a major brand + multiple panel-preset TLS ports open)";
    else if (any_impersonation)
        stack_name = "Xray-core VLESS+Reality (static dest — TLS cert cloned from a major brand)";
    else if (reality_port_count >= 2)
        stack_name = "Xray-core / sing-box (VLESS+Reality, multi-port)";
    else if (xray_reality_primary)
        stack_name = "Xray-core (VLESS+Reality with HTTP fallback)";
    else if (xray_reality_hidden)
        stack_name = "Xray-core (VLESS+Reality, hidden-mode)";
    else if (any_reality)
        stack_name = "Xray / Reality-compatible TLS steering";
    else if (any_canned || any_bad_ver)
        stack_name = "TLS front + Xray/Trojan stream-layer proxy "
                     "(canned fallback response / invalid HTTP version — not a real web server)";
    else if (any_short_val)
        stack_name = "TLS endpoint with a hand-rolled short-lifetime cert "
                     "(validity < 14d — never issued by real CAs; Xray/Trojan quickfire setup)";
    else if (xui_cluster_seen)
        stack_name = "3x-ui/x-ui/Marzban panel install (multiple preset TLS ports open) — "
                     "VLESS/Trojan/Shadowsocks multiplex likely";
    else if (any_ovpn_udp || openset.count(1194) || openset.count(1193))
        stack_name = "OpenVPN (plaintext wire protocol)";
    else if (any_wg)
        stack_name = "WireGuard (default UDP port)";
    else if (openset.count(8388) || openset.count(8488))
        stack_name = "Shadowsocks (naked default port)";
    else if (proxy_middleware_seen)
        stack_name = "TLS front + stream-layer proxy (Xray / Trojan / SS-AEAD) — TLS handshake is clean, "
                     "but the origin silently drops non-TLS bytes instead of returning HTTP 400 like a real web server";
    else if (any_tls && openset.count(443))
        stack_name = "generic TLS / HTTPS origin (no direct VPN signature)";
    else
        stack_name = "no VPN protocol signature identified";

    printf("\n  %sStack identified:%s  %s%s%s\n",
           col(C::BOLD), col(C::RST),
           col(C::CYN), stack_name.c_str(), col(C::RST));

    if (!port_roles.empty()) {
        printf("\n  %sPer-port classification:%s\n", col(C::BOLD), col(C::RST));
        for (auto& [p, role]: port_roles)
            printf("    %s:%-5d%s  %s\n", col(C::CYN), p, col(C::RST), role.c_str());
    }

    // ---- DPI exposure matrix (new in v2.2) -------------------------
    auto axis = [&](const char* name, const char* level, const string& note) {
        const char* c = !strcmp(level,"HIGH")   ? C::RED :
                        !strcmp(level,"MEDIUM") ? C::YEL :
                        !strcmp(level,"LOW")    ? C::GRN :
                        !strcmp(level,"NONE")   ? C::DIM : C::CYN;
        dpi_axes.push_back({name, string(level) + " — " + note});
        printf("    %-36s %s%-6s%s  %s\n", name, col(c), level, col(C::RST), note.c_str());
    };

    // v2.3 — aggregate HTTPS-probe / panel counters used by matrix rows.
    int https_bad_ver_ports = 0, https_no_server_ports = 0, https_empty_ports = 0, https_ok_real_ports = 0;
    for (auto& pf: R.fps) if (pf.https && pf.https->tls_ok) {
        if (pf.https->responded && pf.https->version_anomaly)                                 ++https_bad_ver_ports;
        else if (pf.https->responded && pf.https->server_hdr.empty())                         ++https_no_server_ports;
        else if (!pf.https->responded)                                                        ++https_empty_ports;
        else                                                                                  ++https_ok_real_ports;
    }

    printf("\n  %sDPI exposure matrix:%s\n", col(C::BOLD), col(C::RST));
    // 1. Port-based (TSPU curated list)
    {
        int naive_hits = 0;
        for (int p: {1194, 1723, 500, 4500, 51820, 1701, 8388, 8488, 8090, 10808, 10809})
            if (openset.count(p)) ++naive_hits;
        axis("Port-based (default VPN ports)",
             naive_hits >= 2 ? "HIGH" : naive_hits == 1 ? "MEDIUM" : "LOW",
             naive_hits ? std::to_string(naive_hits) + " default VPN port(s) open" :
                          "no default VPN ports among open set");
    }
    // 2. Protocol handshake signature (plaintext VPN reply)
    {
        bool ovpn = any_ovpn_udp || openset.count(1194);
        bool wg   = any_wg;
        bool ike  = false;
        for (auto& [p,u]: R.udp_probes) if ((p==500||p==4500) && u.responded) ike = true;
        if (ovpn || wg)      axis("Protocol handshake signature", "HIGH",
                                  string(ovpn?"OpenVPN ":"") + (wg?"WireGuard":"") + " signature matched");
        else if (ike)        axis("Protocol handshake signature", "MEDIUM", "IKEv2 responds on control ports");
        else if (any_reality) axis("Protocol handshake signature", "LOW", "TLS 1.3 handshake looks normal (Reality identified by cert-steering, not handshake bytes)");
        else if (any_tls)    axis("Protocol handshake signature", "LOW", "TLS handshake looks normal");
        else                 axis("Protocol handshake signature", "NONE", "no TLS / no VPN protocol replies");
    }
    // 3. Cert-steering (Reality discriminator)
    {
        if (any_reality)            axis("Cert-steering (Reality discriminator)", "HIGH",
                                         "Reality steering pattern positively identified");
        else {
            bool same_cert_seen = false, varies_seen = false;
            for (auto& pf: R.fps) if (pf.sni) {
                if (pf.sni->same_cert_always) same_cert_seen = true;
                else if (!pf.sni->default_cert_only) varies_seen = true;
            }
            if (varies_seen)        axis("Cert-steering (Reality discriminator)", "NONE",
                                         "cert varies per SNI (multi-tenant TLS, not Reality)");
            else if (same_cert_seen) axis("Cert-steering (Reality discriminator)", "NONE",
                                          "single default cert — plain server, not Reality");
            else                    axis("Cert-steering (Reality discriminator)", "NONE",
                                         "no TLS to test");
        }
    }
    // 4. ASN classifier
    //    v2.3: hosting ASN is the NORM for public servers. TSPU does look
    //    at ASN class, but on its own it only enables further checks — it
    //    is not a positive VPN verdict. Downgrade from MEDIUM to LOW/NONE.
    {
        if (hosting_hits >= 2)   axis("ASN classifier (VPS/hosting)", "LOW",
                                      std::to_string(hosting_hits) + " sources classify the ASN as hosting/datacenter — normal for any public server");
        else if (hosting_hits == 1) axis("ASN classifier (VPS/hosting)", "LOW",
                                         "1 source classifies the ASN as hosting (ambiguous)");
        else                     axis("ASN classifier (VPS/hosting)", "NONE",
                                      "no GeoIP source classifies the ASN as hosting");
    }
    // 5. VPN/Proxy tags from threat-intel
    //    v2.3: single-source tag is noise. Only multi-source consensus is
    //    a real signal.
    {
        if (tor_hits) {
            axis("Threat-intel tags (VPN/Proxy/Tor)", "HIGH",
                 std::to_string(tor_hits) + " sources tag this IP as Tor exit");
        } else if (vpn_hits >= 2 || proxy_hits >= 2) {
            string n = std::to_string(vpn_hits) + " VPN / " + std::to_string(proxy_hits) + " proxy tags";
            axis("Threat-intel tags (VPN/Proxy/Tor)", "HIGH", n);
        } else if (vpn_hits || proxy_hits) {
            axis("Threat-intel tags (VPN/Proxy/Tor)", "NONE",
                 "1 single-source tag — false-positive rate too high to count");
        } else {
            axis("Threat-intel tags (VPN/Proxy/Tor)", "NONE", "no VPN/Proxy/Tor tag from any source");
        }
    }
    // 6. Cert freshness + short-validity (v2.3)
    //    short-validity (< 14d total) is NEVER legitimate — LE issues 90d,
    //    commercial CAs issue 30-365d. A 6-day cert is a hand-rolled
    //    short-lived self-signed or a test-CA cert typical of Xray/Trojan
    //    quickfire installs.
    {
        if (cert_short_validity_ports >= 1)
            axis("Cert freshness (new-LE watch)", "HIGH",
                 std::to_string(cert_short_validity_ports) +
                 " port(s) with impossibly short cert validity (<14d total — real CAs never issue this)");
        else if (cert_fresh_ports >= 1)
            axis("Cert freshness (new-LE watch)", "MEDIUM",
                 std::to_string(cert_fresh_ports) + " port(s) with cert <14d old");
        else
            axis("Cert freshness (new-LE watch)", "LOW", "no suspiciously fresh certs");
    }
    // 7. Active junk probing (J3)
    {
        if (j3_ports_checked == 0)   axis("Active junk probing (J3)", "NONE", "no J3 probes ran");
        else if (j3_silent_total >= j3_resp_total && j3_silent_total >= 4)
            axis("Active junk probing (J3)", "MEDIUM",
                 std::to_string(j3_silent_total) + " silent / " + std::to_string(j3_resp_total) +
                 " resp — strict TLS-only posture (fingerprintable by TSPU)");
        else if (j3_resp_total >= j3_silent_total)
            axis("Active junk probing (J3)", "LOW",
                 std::to_string(j3_resp_total) + " responses — looks like a permissive web-origin");
        else
            axis("Active junk probing (J3)", "LOW",
                 std::to_string(j3_silent_total) + " silent / " + std::to_string(j3_resp_total) + " resp");
    }
    // 8. Open-port profile
    //    v2.3: single-port :443 is NOT a red flag on its own — many
    //    corporate reverse-proxies / CDNs look identical. Downgrade.
    //    v2.3: but if the sparse set is dominated by 3x-ui/x-ui/Marzban
    //    panel preset ports, the open-port profile IS anomalous.
    {
        size_t np = R.open_tcp.size();
        if (xui_cluster_seen)
            axis("Open-port profile (sparsity)", "HIGH",
                 std::to_string(np) + " ports open, dominated by the 3x-ui/x-ui/Marzban preset TLS cluster " +
                 std::to_string(xui_cluster_hits) + " hits (2053/2083/2087/2096/8443/…) — installer fingerprint");
        else if (np == 1 && openset.count(443))
            axis("Open-port profile (sparsity)", "LOW",
                 ":443 only — common for reverse-proxies, corporate apps, and single-purpose hosts alike");
        else if (np <= 3 && openset.count(443) && hosting_hits)
            axis("Open-port profile (sparsity)", "LOW",
                 "sparse (<=3 ports) on hosting ASN — ambiguous (minimal corp server / proxy VPS)");
        else if (np >= 8)
            axis("Open-port profile (sparsity)", "NONE",
                 std::to_string(np) + " ports open — diverse service host, clearly not a dedicated proxy");
        else
            axis("Open-port profile (sparsity)", "LOW",
                 std::to_string(np) + " ports open");
    }
    // 9. TLS posture quality
    {
        int bad = tls_not_13_ports + alpn_not_h2_ports + cert_self_signed_ports;
        if (bad >= 2) axis("TLS hygiene (1.3 + h2 + trusted-CA)", "MEDIUM",
                           std::to_string(bad) + " hygiene issues (weak TLS / ALPN / self-signed)");
        else if (bad == 1) axis("TLS hygiene (1.3 + h2 + trusted-CA)", "LOW", "1 hygiene issue");
        else if (any_tls)  axis("TLS hygiene (1.3 + h2 + trusted-CA)", "LOW", "TLS posture is clean (1.3 + h2 + trusted-CA)");
        else               axis("TLS hygiene (1.3 + h2 + trusted-CA)", "NONE", "no TLS observed");
    }
    // 10. Cert impersonation (v2.3) — famous-brand CN on a non-owning ASN.
    //     This is the cheapest tell for a Reality-static setup: someone
    //     points `dest=www.amazon.com` (or Apple/Microsoft/Google/...) and
    //     Reality clones that cert. ASN-to-brand ownership check rules out
    //     legitimate CDN fronting.
    {
        if (any_impersonation) {
            int cnt = 0; string bdom;
            for (auto& pf: R.fps) if (pf.sni && pf.sni->cert_impersonation) {
                ++cnt; if (bdom.empty()) bdom = pf.sni->brand_claimed;
            }
            // Also count server-header brand hits (independent channel).
            int svr_cnt = 0;
            for (auto& pf: R.fps)
                if (pf.https && pf.https->tls_ok && !pf.https->server_hdr.empty()) {
                    string sb = server_header_brand(pf.https->server_hdr);
                    if (!sb.empty() && !asn_owns_brand(sb, asn_orgs_all)) {
                        ++svr_cnt; if (bdom.empty()) bdom = sb;
                    }
                }
            string detail = std::to_string(cnt) + " cert port(s)";
            if (svr_cnt > 0) detail += " + " + std::to_string(svr_cnt) + " Server-header port(s)";
            detail += " claim brand '" + bdom + "' on an ASN that does NOT own it — Reality `dest=` cloning signature";
            axis("Cert impersonation (Reality-static tell)", "HIGH", detail);
        } else {
            axis("Cert impersonation (Reality-static tell)", "NONE",
                 "no cert claims a major-brand domain the ASN doesn't own");
        }
    }
    // 11. Active HTTP-over-TLS probe (v2.3) — after the TLS handshake we
    //     actually send `GET / HTTP/1.1` and read the reply. Real web
    //     origins always answer (200/301/404/502 with a Server: header).
    //     Silence, missing Server, or a malformed HTTP version are the
    //     hard tells for middleware / Xray fallback.
    {
        if (https_bad_ver_ports >= 1) {
            axis("Active HTTP-over-TLS probe", "HIGH",
                 std::to_string(https_bad_ver_ports) +
                 " port(s) returned an invalid HTTP version (HTTP/0.0 or malformed) — no real web server emits this");
        } else if (https_empty_ports >= 1) {
            axis("Active HTTP-over-TLS probe", "MEDIUM",
                 std::to_string(https_empty_ports) +
                 " port(s) accept TLS but return 0 bytes to a valid GET / — stream-layer proxy tell");
        } else if (https_no_server_ports >= 1) {
            axis("Active HTTP-over-TLS probe", "MEDIUM",
                 std::to_string(https_no_server_ports) +
                 " port(s) responded without a Server: header — nginx/Apache/Caddy always set one");
        } else if (https_ok_real_ports >= 1) {
            axis("Active HTTP-over-TLS probe", "LOW",
                 std::to_string(https_ok_real_ports) +
                 " port(s) returned a well-formed HTTP reply with a Server: header — looks like a real web origin");
        } else {
            axis("Active HTTP-over-TLS probe", "NONE", "no TLS port to probe");
        }
    }
    // 12. 3x-ui / x-ui / Marzban panel-port cluster (v2.3) — the panel
    //     installers preset an exact TLS-port set that regular web hosts
    //     almost never open together.
    {
        if (xui_cluster_hits >= 2)
            axis("Panel-port cluster (3x-ui/x-ui/Marzban)", "HIGH",
                 std::to_string(xui_cluster_hits) + " of the preset panel TLS ports are open "
                 "(2053/2083/2087/2096/8443/8880/6443/7443/9443)");
        else if (xui_cluster_hits == 1)
            axis("Panel-port cluster (3x-ui/x-ui/Marzban)", "MEDIUM",
                 "1 panel-preset TLS port open — ambiguous (could be Cloudflare-Origin anyway)");
        else
            axis("Panel-port cluster (3x-ui/x-ui/Marzban)", "NONE",
                 "no panel-preset TLS ports among open set");
    }
    // 13. J3 canned-fallback / HTTP-anomaly aggregate (v2.3) — real web
    //     servers vary their replies per request (different URIs, methods,
    //     headers). An identical byte-exact reply to multiple distinct
    //     probes is a static fallback page that Xray/Trojan wire up.
    {
        int worst = std::max({j3_canned_ports, j3_badver_ports, j3_raw_nonhttp_ports});
        if (j3_canned_ports >= 1 || j3_badver_ports >= 1)
            axis("J3 canned/anomaly aggregate", "HIGH",
                 std::to_string(j3_canned_ports) + " canned / " +
                 std::to_string(j3_badver_ports) + " bad-version / " +
                 std::to_string(j3_raw_nonhttp_ports) + " raw-non-HTTP port(s) — static fallback signature");
        else if (j3_raw_nonhttp_ports >= 1)
            axis("J3 canned/anomaly aggregate", "MEDIUM",
                 std::to_string(j3_raw_nonhttp_ports) + " port(s) return non-HTTP bytes — Shadowsocks/Trojan/custom proxy");
        else if (j3_ports_checked)
            axis("J3 canned/anomaly aggregate", "LOW", "no canned / bad-version / raw-non-HTTP replies");
        else
            axis("J3 canned/anomaly aggregate", "NONE", "no J3 probes ran");
        (void)worst;
    }

    // ---- Signal lists ----------------------------------------------
    printf("\n  %sStrong signals (%zu)%s  [%s!%s = real evidence of VPN/proxy]\n",
           col(C::BOLD), signals_major.size(), col(C::RST), col(C::RED), col(C::RST));
    if (signals_major.empty()) printf("    (none)\n");
    else for (auto& s: signals_major) printf("    %s[!]%s %s\n", col(C::RED), col(C::RST), s.c_str());

    printf("\n  %sSoft signals (%zu)%s  [%s-%s = suggestive pattern, not proof]\n",
           col(C::BOLD), signals_minor.size(), col(C::RST), col(C::YEL), col(C::RST));
    if (signals_minor.empty()) printf("    (none)\n");
    else for (auto& s: signals_minor) printf("    %s[-]%s %s\n", col(C::YEL), col(C::RST), s.c_str());

    printf("\n  %sInformational (%zu)%s  [%si%s = observation only, no penalty — normal sites can have these]\n",
           col(C::BOLD), notes.size(), col(C::RST), col(C::CYN), col(C::RST));
    if (notes.empty()) printf("    (none)\n");
    else for (auto& [tag, s]: notes)
        printf("    %s[i]%s %s%s%s  %s\n",
               col(C::CYN), col(C::RST),
               col(C::DIM), tag.c_str(), col(C::RST), s.c_str());

    printf("\n  %sFinal score:%s %s%d/100%s  verdict: %s%s%s\n",
           col(C::BOLD), col(C::RST), col(C::BOLD), score, col(C::RST),
           col(color), R.label.c_str(), col(C::RST));

    // ---- Hardening suggestions (actionable) ------------------------
    // Built from strong/soft signals AND from informational observations —
    // so every "[i] single-443" etc. comes with a concrete fix even
    // though it didn't cost any score.
    printf("\n  %sHardening suggestions:%s\n", col(C::BOLD), col(C::RST));
    auto sug = [](const char* tag, const char* body) {
        printf("    %s[%s]%s\n      %s\n", col(C::GRN), tag, col(C::RST), body);
    };

    bool any_sug = false;
    auto has_note = [&](const string& t) {
        for (auto& [k,_]: notes) if (k == t) return true;
        return false;
    };

    // Protocol-level hardening
    if (xray_reality_primary && xray_reality_hidden) {
        sug("reality-mixed",
            "Mixed Reality config: one port uses HTTP-fallback, another is hidden-mode.\n"
            "      The hidden port exposes the silent-on-junk DPI signature. Either drop\n"
            "      the duplicate listener, or configure the Reality `fallback` block so\n"
            "      EVERY port returns HTTP 400/502 on non-handshake traffic (match nginx).");
        any_sug = true;
    } else if (xray_reality_hidden) {
        sug("reality-hidden",
            "Reality hidden-mode: TLS handshake ok, but non-TLS bytes are silently dropped.\n"
            "      That pattern is DPI-detectable (TSPU/GFW fingerprint it).\n"
            "      Fix: set `dest=` to a real HTTPS site you don't control, and configure\n"
            "      `fallback` so the server returns its own 400/502 page on unrecognised bytes.");
        any_sug = true;
    } else if (xray_reality_primary) {
        sug("reality-ok",
            "Reality HTTP-fallback is wired correctly: junk bytes get HTTP 400, which is\n"
            "      indistinguishable from nginx/Apache. No action needed.");
        any_sug = true;
    }
    if (proxy_middleware_seen) {
        sug("proxy-middleware",
            "TLS is clean on this port, but the origin silently drops every HTTP-junk probe\n"
            "      instead of returning HTTP 400 like nginx/Apache/Caddy would. That silence\n"
            "      is the proxy-middleware signature TSPU actively tests for. Fix: put a real\n"
            "      nginx in front that handles both the TLS handshake AND the HTTP fallback,\n"
            "      so non-TLS bytes hit nginx's own 400 page.");
        any_sug = true;
    }
    if (reality_port_count >= 2) {
        char buf[256];
        snprintf(buf, sizeof(buf),
            "Reality is listening on %d ports of the same IP. ASN/port sweeps flag multi-port\n"
            "      TLS-steering anomalies; keep Reality on a single port and populate the\n"
            "      other ports with real services (or close them).", reality_port_count);
        sug("reality-multiport", buf);
        any_sug = true;
    }

    // Hardened-VPN-protocol hardening
    if (any_ovpn_udp || openset.count(1194) || openset.count(1193)) {
        sug("openvpn",
            "OpenVPN on default port 1194: TSPU/GFW drop this on the first HARD_RESET.\n"
            "      Wrap in TLS (stunnel / Cloak) or migrate to VLESS+Reality on :443.");
        any_sug = true;
    }
    if (any_wg) {
        sug("wireguard",
            "WireGuard on UDP/51820 answers its handshake — the handshake is a fixed-offset\n"
            "      signature TSPU already has. Use amneziawg (obfuscated WG) or tunnel WG\n"
            "      inside a TCP-TLS wrapper if you need to survive active DPI.");
        any_sug = true;
    }
    if (openset.count(8388) || openset.count(8488)) {
        sug("shadowsocks",
            "Shadowsocks on its default port is trivially probed via AEAD-length oracle.\n"
            "      Wrap it with v2ray/xray stream-settings + TLS, or drop it for VLESS+Reality.");
        any_sug = true;
    }
    if (openset.count(3389)) {
        sug("rdp",
            "RDP/3389 is reachable from the Internet — not a VPN issue, but a critical\n"
            "      attack surface. Firewall it; expose only through a jump host or VPN.");
        any_sug = true;
    }

    // --- v2.3 hardening ------------------------------------------------
    if (any_impersonation) {
        // Brand domain: prefer the TLS-cert brand if we caught it there,
        // else fall back to the Server-header-derived brand.
        string bdom;
        for (auto& pf: R.fps)
            if (pf.sni && pf.sni->cert_impersonation && !pf.sni->brand_claimed.empty()) {
                bdom = pf.sni->brand_claimed; break;
            }
        if (bdom.empty())
            for (auto& pf: R.fps)
                if (pf.https && pf.https->tls_ok && !pf.https->server_hdr.empty()) {
                    string sb = server_header_brand(pf.https->server_hdr);
                    if (!sb.empty()) { bdom = sb; break; }
                }
        string body =
            "Reality `dest=` points at '" + bdom + "', so the endpoint serves a cert (and/or\n"
            "      `Server:` banner) for that brand on an ASN that doesn't own it. This is the\n"
            "      cheapest tell in the book — DPI engines cross-reference cert subject + HTTP\n"
            "      Server-header + ASN ownership. Pick a `dest=` on the SAME ASN/CDN as your VPS\n"
            "      (e.g. a small regional site on the same hosting provider's netblock), or —\n"
            "      safer — move to a real domain you own with its own full LE chain. Never pick\n"
            "      amazon/apple/microsoft/google/cloudflare on a random VPS.";
        sug("cert-impersonation", body.c_str());
        any_sug = true;
    }
    if (cert_short_validity_ports > 0) {
        sug("cert-short-validity",
            "One of the certs has total validity < 14 days. Real CAs never issue that:\n"
            "      Let's Encrypt = 90d, commercial = 30d+. A sub-14d cert is a hand-rolled\n"
            "      short-lifetime self-signed or a test-CA issuance — classic Xray/Trojan\n"
            "      quickfire setup. Fix: switch to LE (certbot / lego / acme.sh) with auto-renew,\n"
            "      OR front the origin behind a CDN so visitors see the CDN's cert instead.");
        any_sug = true;
    }
    if (j3_canned_ports > 0 || j3_badver_ports > 0) {
        sug("canned-fallback",
            "At least one port returns a canned fallback (same byte-exact first line for\n"
            "      different probes) or a malformed HTTP version — classic Xray `fallback` /\n"
            "      Trojan default handler. Real nginx/Apache/Caddy vary their replies per\n"
            "      request (different URIs -> different statuses, different bodies). Fix:\n"
            "      put a real nginx in front with a proper error-page map, and make the Xray\n"
            "      `fallbacks` point at that nginx so non-handshake bytes get REAL HTTP.");
        any_sug = true;
    }
    if (https_bad_ver_ports > 0) {
        sug("http-version-anomaly",
            "Active HTTP-over-TLS probe got back an invalid HTTP version (HTTP/0.0 or\n"
            "      similar). No real web server emits that — it's generated by Xray/Trojan's\n"
            "      stream handler when it partially decodes a non-protocol request. Same fix as\n"
            "      above: wire the `fallback` block to a real nginx so it emits `HTTP/1.1 400`.");
        any_sug = true;
    }
    if (https_empty_ports > 0 && !any_reality) {
        sug("http-silent-origin",
            "Active HTTP-over-TLS probe completed the handshake but got zero response bytes\n"
            "      back to a plain `GET /`. A legitimate web origin always answers (200 / 301 /\n"
            "      404 / 502). Silence is the stream-layer-proxy signature (Xray/Trojan/SS-AEAD\n"
            "      that only speaks its own framing). Fix: add an HTTP `fallback` that proxies\n"
            "      to a real web root so `GET /` always returns something with a `Server:` header.");
        any_sug = true;
    }
    if (https_no_server_ports > 0 && !any_reality) {
        sug("http-missing-server-header",
            "The origin replies to HTTP but without a `Server:` header. nginx/Apache/Caddy/CDNs\n"
            "      set one unambiguously. Absence is a middleware / custom-handler tell — fix by\n"
            "      fronting the origin with a real nginx that sets `server_tokens on` (or even\n"
            "      forges a plausible `Server: cloudflare` / `Server: nginx/1.24.0`).");
        any_sug = true;
    }
    if (xui_cluster_seen) {
        sug("xui-panel",
            "The open-port profile matches the 3x-ui / x-ui / Marzban panel installer set\n"
            "      (2053/2083/2087/2096/8443/8880/6443/7443/9443). That exact cluster is the\n"
            "      single strongest fingerprint a TSPU-class DPI engine looks for. Fix: close\n"
            "      the unused panel ports (keep ONE listener on :443 on the real Reality inbound),\n"
            "      firewall the panel UI to admin source IPs only, and avoid the defaults.");
        any_sug = true;
    }

    // TLS hygiene
    for (auto& pf: R.fps)
        if (pf.tls && pf.tls->ok && pf.tls->version != "TLSv1.3") {
            char buf[256];
            snprintf(buf, sizeof(buf),
                "Upgrade TLS to 1.3 on :%d (current: %s). Modern clients expect TLS 1.3;\n"
                "      VLESS/Reality requires it. Bump the OpenSSL/nginx config.",
                pf.port, pf.tls->version.c_str());
            sug("tls-version", buf);
            any_sug = true;
        }
    if (cert_self_signed_ports > 0) {
        sug("tls-self-signed",
            "Self-signed TLS cert: browsers reject it instantly, and it is the classic\n"
            "      Shadowsocks/Trojan/test-setup signature. Issue a real cert (Let's\n"
            "      Encrypt on a real domain) or front the endpoint with a CDN.");
        any_sug = true;
    }

    // Observation-driven hardening (from notes[])
    if (has_note("single-443")) {
        sug("port-profile",
            "Only :443 is reachable. Not a red flag on its own — TSPU classifies by the\n"
            "      bytes on the wire, not by how many ports you open. But if you want to\n"
            "      look like a typical corporate web host, open :80 with a 301 HTTP→HTTPS\n"
            "      redirect, serve a real-looking page on `/` (not the default nginx page),\n"
            "      and optionally add a firewalled :22 or :25 so the host has 'context'.");
        any_sug = true;
    }
    if (has_note("ssh-22")) {
        sug("ssh-banner",
            "SSH/22 is open with a default banner. It doesn't tag you as a VPN, but it\n"
            "      does tell every ASN-sweep that you run a real server. Move SSH to a\n"
            "      high port (40000+) and firewall it to known admin source IPs.");
        any_sug = true;
    }
    if (cert_fresh_ports > 0 && sparse_vps_profile) {
        sug("cert-fresh",
            "Fresh cert (<14d) on a sparse-port hosting host is a classical 'new VLESS\n"
            "      instance' fingerprint. Fix: use a long-lived wildcard cert on a domain\n"
            "      you've owned >90d, or front the origin behind a CDN (Cloudflare free\n"
            "      tier) so visitors see the CDN's cert instead of yours.");
        any_sug = true;
    } else if (has_note("cert-fresh")) {
        sug("cert-fresh",
            "Fresh cert (<14d) is normal LE rotation on its own. Only becomes a signal\n"
            "      when combined with hosting-ASN + sparse port profile. No action needed\n"
            "      unless you're also on a single-purpose VPS profile.");
        any_sug = true;
    }
    if (has_note("asn-hosting") && !any_reality && !proxy_middleware_seen) {
        sug("asn-hosting",
            "Being on a hosting ASN is the norm for every public server — this alone is\n"
            "      NOT a VPN signal. TSPU does use ASN as a gate for deeper checks, but\n"
            "      what it then verifies is the TLS/HTTP behaviour, not the ASN itself.\n"
            "      If you want to escape the 'hosting ASN' category entirely, the only\n"
            "      clean move is a residential-ASN proxy in front (rare) or a CDN.");
        any_sug = true;
    }
    if (has_note("geo-vpn") || has_note("geo-proxy")) {
        sug("threat-intel",
            "One of the 9 GeoIP providers (3 EU / 3 RU / 3 global) tagged this IP as\n"
            "      VPN/proxy. Single-source tags are very noisy (false positives are common).\n"
            "      Fix only if it blocks you in practice: rotate to a fresh IP, or if IP\n"
            "      reputation really matters to your use-case, use an IP on a residential /\n"
            "      business ASN instead of hosting.");
        any_sug = true;
    }

    if (!any_sug)
        printf("    (no actionable hardening — protocol posture looks clean)\n");

    // ---- Threat-model note ------------------------------------------
    printf("\n  %sThreat-model note:%s\n", col(C::BOLD), col(C::RST));
    printf("    TSPU/GFW classify a destination by what the IP actually does on the wire —\n"
           "    TLS handshake bytes, cert-steering, active HTTP-over-TLS reply shape,\n"
           "    reactions to junk, default-port replies. IP 'reputation' (hosting ASN /\n"
           "    GeoIP VPN tag) is only a coarse pre-filter, so this tool treats it as\n"
           "    informational and focuses the score on the actual protocol signatures at\n"
           "    the endpoint. v2.3 strong signals are: cert impersonation (brand CN on\n"
           "    non-owning ASN), short-validity certs (<14d), canned-fallback pages,\n"
           "    HTTP-version anomalies, and 3x-ui/x-ui/Marzban panel-port clusters — these\n"
           "    are expensive-to-fake tells that map directly to Xray/Reality/Trojan.\n"
           "    If every strong signal is 'none' and soft signals are quiet, the host is\n"
           "    essentially invisible to passive DPI regardless of what the ASN looks like.\n");

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
    printf("GeoIP sources (9 providers, 3 EU / 3 RU / 3 global):\n");
    printf("  EU:     ipapi.is, iplocate.io, freeipapi.com\n");
    printf("  RU:     2ip.io/2ip.me, ip-api.com/ru, sypexgeo.net\n");
    printf("  global: ip-api.com, ipwho.is, ipinfo.io\n");
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
            auto f1 = std::async(std::launch::async, geo_ipapi_is,   t);   // EU
            auto f2 = std::async(std::launch::async, geo_iplocate,   t);
            auto f3 = std::async(std::launch::async, geo_freeipapi,  t);
            auto f4 = std::async(std::launch::async, geo_2ip_ru,     t);   // RU
            auto f5 = std::async(std::launch::async, geo_ipapi_ru,   t);
            auto f6 = std::async(std::launch::async, geo_sypex,      t);
            auto f7 = std::async(std::launch::async, geo_ip_api_com, t);   // global
            auto f8 = std::async(std::launch::async, geo_ipwho_is,   t);
            auto f9 = std::async(std::launch::async, geo_ipinfo_io,  t);
            printf("  %s-- EU --%s\n", col(C::BOLD), col(C::RST));
            print_geo(f1.get()); print_geo(f2.get()); print_geo(f3.get());
            printf("  %s-- RU --%s\n", col(C::BOLD), col(C::RST));
            print_geo(f4.get()); print_geo(f5.get()); print_geo(f6.get());
            printf("  %s-- global --%s\n", col(C::BOLD), col(C::RST));
            print_geo(f7.get()); print_geo(f8.get()); print_geo(f9.get());
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
            auto f1 = std::async(std::launch::async, geo_ipapi_is,   ip);   // EU
            auto f2 = std::async(std::launch::async, geo_iplocate,   ip);
            auto f3 = std::async(std::launch::async, geo_freeipapi,  ip);
            auto f4 = std::async(std::launch::async, geo_2ip_ru,     ip);   // RU
            auto f5 = std::async(std::launch::async, geo_ipapi_ru,   ip);
            auto f6 = std::async(std::launch::async, geo_sypex,      ip);
            auto f7 = std::async(std::launch::async, geo_ip_api_com, ip);   // global
            auto f8 = std::async(std::launch::async, geo_ipwho_is,   ip);
            auto f9 = std::async(std::launch::async, geo_ipinfo_io,  ip);
            printf("  %s-- EU --%s\n", col(C::BOLD), col(C::RST));
            print_geo(f1.get()); print_geo(f2.get()); print_geo(f3.get());
            printf("  %s-- RU --%s\n", col(C::BOLD), col(C::RST));
            print_geo(f4.get()); print_geo(f5.get()); print_geo(f6.get());
            printf("  %s-- global --%s\n", col(C::BOLD), col(C::RST));
            print_geo(f7.get()); print_geo(f8.get()); print_geo(f9.get());
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
