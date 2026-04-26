#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

namespace blin {

using Bytes = std::vector<std::uint8_t>;

enum class Format : std::uint8_t {
    Text     = 0,
    Markdown = 1,
    Code     = 2,
};

struct File {
    std::string name;
    std::string mime;
    Bytes       body;
};

struct Payload {
    Format               format = Format::Text;
    std::string          lang;
    std::string          text;
    std::optional<File>  file;
};

Bytes   packPayload(const Payload& p);
Payload unpackPayload(const Bytes& b);

}  // namespace blin
