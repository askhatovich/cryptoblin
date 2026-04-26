#include "http.h"

#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/error.h>
#include <mbedtls/net_sockets.h>
#include <mbedtls/ssl.h>
#include <mbedtls/x509_crt.h>

#include <algorithm>
#include <array>
#include <cctype>
#include <cstring>
#include <stdexcept>
#include <string>

namespace blin {

namespace {

std::string toLower(std::string s) {
    for (auto& c : s) {
        c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    }
    return s;
}

std::string trim(std::string s) {
    auto issp = [](unsigned char c) { return c == ' ' || c == '\t' || c == '\r' || c == '\n'; };
    while (!s.empty() && issp(static_cast<unsigned char>(s.front()))) {
        s.erase(s.begin());
    }
    while (!s.empty() && issp(static_cast<unsigned char>(s.back()))) {
        s.pop_back();
    }
    return s;
}

// Plain TCP transport. Uses mbedtls_net_* — a thin wrapper over Berkeley
// sockets on POSIX and WinSock on Windows — to keep the file portable.
class PlainTransport {
public:
    PlainTransport(const std::string& host, int port) {
        mbedtls_net_init(&net_);
        const auto pstr = std::to_string(port);
        if (mbedtls_net_connect(&net_, host.c_str(), pstr.c_str(),
                                MBEDTLS_NET_PROTO_TCP) != 0) {
            throw std::runtime_error("connect to " + host + " failed");
        }
    }
    ~PlainTransport() {
        mbedtls_net_free(&net_);
    }

    void send(const std::uint8_t* data, std::size_t n) {
        std::size_t sent = 0;
        while (sent < n) {
            const int k = mbedtls_net_send(&net_, data + sent, n - sent);
            if (k <= 0) {
                throw std::runtime_error("send failed");
            }
            sent += static_cast<std::size_t>(k);
        }
    }
    std::size_t recv(std::uint8_t* buf, std::size_t n) {
        const int k = mbedtls_net_recv(&net_, buf, n);
        if (k < 0) {
            throw std::runtime_error("recv failed");
        }
        return static_cast<std::size_t>(k);
    }

private:
    mbedtls_net_context net_{};
};

// mbedTLS-wrapped transport.
class TlsTransport {
public:
    TlsTransport(const std::string& host, int port) {
        mbedtls_net_init(&net_);
        mbedtls_ssl_init(&ssl_);
        mbedtls_ssl_config_init(&conf_);
        mbedtls_ctr_drbg_init(&drbg_);
        mbedtls_entropy_init(&entropy_);
        mbedtls_x509_crt_init(&cacert_);

        const char* pers = "blin";
        if (mbedtls_ctr_drbg_seed(&drbg_, mbedtls_entropy_func, &entropy_,
                                   reinterpret_cast<const unsigned char*>(pers),
                                   std::strlen(pers)) != 0) {
            throw std::runtime_error("ctr_drbg_seed failed");
        }

        // Load system CA bundle. Try a few common paths.
        const std::array<const char*, 5> caPaths{
            "/etc/ssl/certs/ca-certificates.crt",
            "/etc/pki/tls/certs/ca-bundle.crt",
            "/etc/ssl/cert.pem",
            "/etc/ssl/ca-bundle.pem",
            "/etc/ssl/certs",
        };
        bool loaded = false;
        for (auto* p : caPaths) {
            // Try as file first, then as directory.
            if (mbedtls_x509_crt_parse_file(&cacert_, p) >= 0) {
                loaded = true;
                break;
            }
            if (mbedtls_x509_crt_parse_path(&cacert_, p) >= 0) {
                loaded = true;
                break;
            }
        }
        if (!loaded) {
            throw std::runtime_error("could not load system CA bundle");
        }

        const auto pstr = std::to_string(port);
        if (mbedtls_net_connect(&net_, host.c_str(), pstr.c_str(),
                                MBEDTLS_NET_PROTO_TCP) != 0) {
            throw std::runtime_error("tls connect to " + host + " failed");
        }
        if (mbedtls_ssl_config_defaults(&conf_, MBEDTLS_SSL_IS_CLIENT,
                                         MBEDTLS_SSL_TRANSPORT_STREAM,
                                         MBEDTLS_SSL_PRESET_DEFAULT) != 0) {
            throw std::runtime_error("ssl_config_defaults failed");
        }
        mbedtls_ssl_conf_authmode(&conf_, MBEDTLS_SSL_VERIFY_REQUIRED);
        mbedtls_ssl_conf_ca_chain(&conf_, &cacert_, nullptr);
        mbedtls_ssl_conf_rng(&conf_, mbedtls_ctr_drbg_random, &drbg_);

        if (mbedtls_ssl_setup(&ssl_, &conf_) != 0) {
            throw std::runtime_error("ssl_setup failed");
        }
        if (mbedtls_ssl_set_hostname(&ssl_, host.c_str()) != 0) {
            throw std::runtime_error("ssl_set_hostname failed");
        }
        mbedtls_ssl_set_bio(&ssl_, &net_, mbedtls_net_send, mbedtls_net_recv, nullptr);

        int rc;
        while ((rc = mbedtls_ssl_handshake(&ssl_)) != 0) {
            if (rc != MBEDTLS_ERR_SSL_WANT_READ && rc != MBEDTLS_ERR_SSL_WANT_WRITE) {
                char buf[256];
                mbedtls_strerror(rc, buf, sizeof(buf));
                throw std::runtime_error(std::string("tls handshake failed: ") + buf);
            }
        }
    }

    ~TlsTransport() {
        mbedtls_ssl_close_notify(&ssl_);
        mbedtls_x509_crt_free(&cacert_);
        mbedtls_ssl_free(&ssl_);
        mbedtls_ssl_config_free(&conf_);
        mbedtls_ctr_drbg_free(&drbg_);
        mbedtls_entropy_free(&entropy_);
        mbedtls_net_free(&net_);
    }

    void send(const std::uint8_t* data, std::size_t n) {
        std::size_t sent = 0;
        while (sent < n) {
            const auto k = mbedtls_ssl_write(&ssl_, data + sent, n - sent);
            if (k <= 0) {
                if (k == MBEDTLS_ERR_SSL_WANT_READ || k == MBEDTLS_ERR_SSL_WANT_WRITE) {
                    continue;
                }
                throw std::runtime_error("tls write failed");
            }
            sent += static_cast<std::size_t>(k);
        }
    }
    std::size_t recv(std::uint8_t* buf, std::size_t n) {
        for (;;) {
            const auto k = mbedtls_ssl_read(&ssl_, buf, n);
            if (k > 0) {
                return static_cast<std::size_t>(k);
            }
            if (k == MBEDTLS_ERR_SSL_PEER_CLOSE_NOTIFY || k == 0) {
                return 0;
            }
            if (k == MBEDTLS_ERR_SSL_WANT_READ || k == MBEDTLS_ERR_SSL_WANT_WRITE) {
                continue;
            }
            throw std::runtime_error("tls read failed");
        }
    }

private:
    mbedtls_net_context       net_{};
    mbedtls_ssl_context       ssl_{};
    mbedtls_ssl_config        conf_{};
    mbedtls_ctr_drbg_context  drbg_{};
    mbedtls_entropy_context   entropy_{};
    mbedtls_x509_crt          cacert_{};
};

template <class Transport>
Response doRequest(Transport& t, const ServerUrl& server, const Request& req) {
    // --- Build request bytes.
    std::string head;
    head.reserve(256 + req.headers.size() * 32);
    head += req.method;
    head += ' ';
    head += req.path;
    head += " HTTP/1.1\r\n";
    head += "Host: " + server.host;
    if ((server.https && server.port != 443) || (!server.https && server.port != 80)) {
        head += ":" + std::to_string(server.port);
    }
    head += "\r\n";
    head += "User-Agent: blin/0.1\r\n";
    head += "Connection: close\r\n";
    head += "Content-Length: " + std::to_string(req.body.size()) + "\r\n";
    bool hasContentType = false;
    for (const auto& [k, v] : req.headers) {
        if (toLower(k) == "content-type") hasContentType = true;
        head += k + ": " + v + "\r\n";
    }
    if (!hasContentType && !req.body.empty()) {
        head += "Content-Type: application/octet-stream\r\n";
    }
    head += "\r\n";

    t.send(reinterpret_cast<const std::uint8_t*>(head.data()), head.size());
    if (!req.body.empty()) {
        t.send(req.body.data(), req.body.size());
    }

    // --- Drain entire response into buffer.
    Bytes raw;
    raw.reserve(8192);
    std::array<std::uint8_t, 8192> chunk{};
    for (;;) {
        const auto n = t.recv(chunk.data(), chunk.size());
        if (n == 0) break;
        raw.insert(raw.end(), chunk.begin(), chunk.begin() + n);
    }

    // --- Parse status line + headers.
    Response r;
    auto find = [&](std::size_t from, const char* needle) -> std::size_t {
        const auto nlen = std::strlen(needle);
        if (raw.size() < nlen) return std::string::npos;
        for (std::size_t i = from; i + nlen <= raw.size(); ++i) {
            if (std::memcmp(raw.data() + i, needle, nlen) == 0) {
                return i;
            }
        }
        return std::string::npos;
    };
    const auto sep = find(0, "\r\n\r\n");
    if (sep == std::string::npos) {
        throw std::runtime_error("malformed HTTP response");
    }
    const std::string headBlob(reinterpret_cast<const char*>(raw.data()), sep);
    const auto firstLineEnd = headBlob.find("\r\n");
    const std::string statusLine = headBlob.substr(0, firstLineEnd);
    {
        const auto sp1 = statusLine.find(' ');
        const auto sp2 = statusLine.find(' ', sp1 + 1);
        if (sp1 == std::string::npos || sp2 == std::string::npos) {
            throw std::runtime_error("bad status line");
        }
        r.status = std::stoi(statusLine.substr(sp1 + 1, sp2 - sp1 - 1));
    }
    std::size_t pos = firstLineEnd + 2;
    while (pos < headBlob.size()) {
        const auto eol = headBlob.find("\r\n", pos);
        const auto line = headBlob.substr(pos, eol - pos);
        pos = (eol == std::string::npos) ? headBlob.size() : eol + 2;
        if (line.empty()) continue;
        const auto colon = line.find(':');
        if (colon == std::string::npos) continue;
        const auto k = toLower(trim(line.substr(0, colon)));
        const auto v = trim(line.substr(colon + 1));
        r.headers[k] = v;
    }

    // --- Body. Either fixed Content-Length or chunked.
    const auto bodyStart = sep + 4;
    const auto& te = r.headers["transfer-encoding"];
    if (te.find("chunked") != std::string::npos) {
        std::size_t p = bodyStart;
        while (p < raw.size()) {
            const auto crlf = std::string(reinterpret_cast<const char*>(raw.data() + p),
                                          raw.size() - p).find("\r\n");
            if (crlf == std::string::npos) break;
            const std::string sizeLine(reinterpret_cast<const char*>(raw.data() + p), crlf);
            const auto semi = sizeLine.find(';');
            const std::string sizeHex = (semi == std::string::npos)
                                         ? sizeLine : sizeLine.substr(0, semi);
            std::size_t chunkLen = 0;
            try {
                chunkLen = std::stoul(sizeHex, nullptr, 16);
            } catch (...) {
                break;
            }
            p += crlf + 2;
            if (chunkLen == 0) break;
            if (p + chunkLen > raw.size()) break;
            r.body.insert(r.body.end(), raw.begin() + p, raw.begin() + p + chunkLen);
            p += chunkLen;
            if (p + 2 > raw.size()) break;
            p += 2;  // trailing CRLF
        }
    } else {
        r.body.assign(raw.begin() + bodyStart, raw.end());
    }
    return r;
}

}  // namespace

Response httpDo(const ServerUrl& server, const Request& req) {
    if (server.https) {
        TlsTransport t(server.host, server.port);
        return doRequest(t, server, req);
    } else {
        PlainTransport t(server.host, server.port);
        return doRequest(t, server, req);
    }
}

}  // namespace blin
