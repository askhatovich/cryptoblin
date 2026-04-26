#pragma once

#include "url.h"

#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace blin {

using Bytes = std::vector<std::uint8_t>;

struct Response {
    int                                status = 0;
    std::map<std::string, std::string> headers;   // lower-cased keys
    Bytes                              body;
};

struct Request {
    std::string                        method;          // "GET" / "POST" / "DELETE"
    std::string                        path;            // e.g. "/api/config"
    std::map<std::string, std::string> headers;
    Bytes                              body;
};

Response httpDo(const ServerUrl& server, const Request& req);

}  // namespace blin
