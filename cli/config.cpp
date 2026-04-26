#include "config.h"

#include <cstdlib>
#include <fstream>
#include <string>

namespace blin {

namespace {

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

}  // namespace

std::string loadServer() {
    const char* home = std::getenv("HOME");
    if (!home || !*home) {
        return kDefaultServer;
    }
    const std::string path =
        std::string(home) + "/.config/askhatovich/cryptoblin/config.conf";
    std::ifstream f(path);
    if (!f) {
        return kDefaultServer;
    }
    std::string line;
    while (std::getline(f, line)) {
        line = trim(line);
        if (line.empty() || line[0] == '#') {
            continue;
        }
        const auto eq = line.find('=');
        if (eq == std::string::npos) {
            continue;
        }
        const auto k = trim(line.substr(0, eq));
        const auto v = trim(line.substr(eq + 1));
        if (k == "SERVER" && !v.empty()) {
            return v;
        }
    }
    return kDefaultServer;
}

}  // namespace blin
