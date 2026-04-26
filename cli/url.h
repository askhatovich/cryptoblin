#pragma once

#include <string>

namespace blin {

struct ServerUrl {
    bool        https = true;
    std::string host;
    int         port = 0;   // 0 = scheme default
    std::string path = "/"; // base path; usually "/"
};

// Parse a server URL like "https://paste.dotcpp.ru" or "http://localhost:8080".
ServerUrl parseServerUrl(const std::string& s);

struct PasteUrl {
    enum class Kind { View, Delete };
    Kind        kind        = Kind::View;
    std::string id;
    std::string seed;        // View only
    bool        hasPassword  = false;
    std::string deleteToken; // Delete only (base64)
};

// Accepts either a full URL with a fragment, or just the fragment portion.
PasteUrl parsePasteUrl(const std::string& s);

std::string buildViewUrl(const std::string& server,
                         const std::string& id, const std::string& seed,
                         bool hasPassword);
std::string buildDeleteUrl(const std::string& server,
                           const std::string& id, const std::string& tokenB64);

}  // namespace blin
