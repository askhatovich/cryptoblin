#include "url.h"

#include <cctype>
#include <stdexcept>

namespace blin {

namespace {

bool isAlnum8(const std::string& s) {
    if (s.size() != 8) {
        return false;
    }
    for (char c : s) {
        if (!std::isalnum(static_cast<unsigned char>(c))) {
            return false;
        }
    }
    return true;
}

}  // namespace

ServerUrl parseServerUrl(const std::string& s) {
    ServerUrl u;
    std::string rest = s;
    if (rest.rfind("https://", 0) == 0) {
        u.https = true;
        rest = rest.substr(8);
    } else if (rest.rfind("http://", 0) == 0) {
        u.https = false;
        rest = rest.substr(7);
    } else {
        throw std::runtime_error("server URL must begin with http:// or https://");
    }
    const auto slash = rest.find('/');
    std::string hostport = (slash == std::string::npos) ? rest : rest.substr(0, slash);
    if (slash != std::string::npos) {
        u.path = rest.substr(slash);
    }
    const auto colon = hostport.rfind(':');
    if (colon != std::string::npos && hostport.find(']') == std::string::npos) {
        u.host = hostport.substr(0, colon);
        u.port = std::stoi(hostport.substr(colon + 1));
    } else {
        u.host = hostport;
        u.port = u.https ? 443 : 80;
    }
    if (u.host.empty()) {
        throw std::runtime_error("server URL is missing the host");
    }
    if (u.path.empty()) {
        u.path = "/";
    }
    return u;
}

PasteUrl parsePasteUrl(const std::string& s) {
    // Find the fragment portion. Accept full URL or bare fragment.
    std::string frag;
    const auto h = s.find('#');
    if (h != std::string::npos) {
        frag = s.substr(h + 1);
    } else {
        frag = s;
    }
    if (frag.empty()) {
        throw std::runtime_error("URL fragment is empty");
    }

    PasteUrl out;
    if (frag.rfind("del:", 0) == 0) {
        out.kind = PasteUrl::Kind::Delete;
        const auto rest = frag.substr(4);
        const auto colon = rest.find(':');
        if (colon == std::string::npos) {
            throw std::runtime_error("delete URL must be del:<id>:<token>");
        }
        out.id = rest.substr(0, colon);
        out.deleteToken = rest.substr(colon + 1);
        if (!isAlnum8(out.id) || out.deleteToken.empty()) {
            throw std::runtime_error("delete URL is malformed");
        }
        return out;
    }

    out.kind = PasteUrl::Kind::View;
    const auto c1 = frag.find(':');
    if (c1 == std::string::npos) {
        throw std::runtime_error("view URL must be <id>:<seed>[:p]");
    }
    out.id = frag.substr(0, c1);
    const auto rest = frag.substr(c1 + 1);
    const auto c2 = rest.find(':');
    if (c2 == std::string::npos) {
        out.seed = rest;
    } else {
        out.seed = rest.substr(0, c2);
        if (rest.substr(c2 + 1) == "p") {
            out.hasPassword = true;
        } else {
            throw std::runtime_error("unknown URL flag");
        }
    }
    if (!isAlnum8(out.id) || !isAlnum8(out.seed)) {
        throw std::runtime_error("view URL is malformed");
    }
    return out;
}

std::string buildViewUrl(const std::string& server,
                         const std::string& id, const std::string& seed,
                         bool hasPassword) {
    return server + "/#" + id + ":" + seed + (hasPassword ? ":p" : "");
}

std::string buildDeleteUrl(const std::string& server,
                           const std::string& id, const std::string& tokenB64) {
    return server + "/#del:" + id + ":" + tokenB64;
}

}  // namespace blin
