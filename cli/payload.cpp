#include "payload.h"

#include <stdexcept>

namespace blin {

namespace {

void putU16(Bytes& out, std::uint16_t v) {
    out.push_back(static_cast<std::uint8_t>(v >> 8));
    out.push_back(static_cast<std::uint8_t>(v & 0xff));
}

void putU32(Bytes& out, std::uint32_t v) {
    out.push_back(static_cast<std::uint8_t>((v >> 24) & 0xff));
    out.push_back(static_cast<std::uint8_t>((v >> 16) & 0xff));
    out.push_back(static_cast<std::uint8_t>((v >>  8) & 0xff));
    out.push_back(static_cast<std::uint8_t>( v        & 0xff));
}

std::uint16_t readU16(const Bytes& b, std::size_t& o) {
    if (o + 2 > b.size()) {
        throw std::runtime_error("payload truncated");
    }
    const auto v = (std::uint16_t(b[o]) << 8) | std::uint16_t(b[o + 1]);
    o += 2;
    return v;
}

std::uint32_t readU32(const Bytes& b, std::size_t& o) {
    if (o + 4 > b.size()) {
        throw std::runtime_error("payload truncated");
    }
    const auto v = (std::uint32_t(b[o    ]) << 24)
                 | (std::uint32_t(b[o + 1]) << 16)
                 | (std::uint32_t(b[o + 2]) <<  8)
                 |  std::uint32_t(b[o + 3]);
    o += 4;
    return v;
}

void putBytes(Bytes& out, const std::uint8_t* p, std::size_t n) {
    out.insert(out.end(), p, p + n);
}

}  // namespace

Bytes packPayload(const Payload& p) {
    const auto& langB = p.lang;
    const auto& textB = p.text;
    const std::string emptyName, emptyMime;
    const auto& nameB = p.file ? p.file->name : emptyName;
    const auto& mimeB = p.file ? p.file->mime : emptyMime;
    const Bytes  emptyFile;
    const Bytes& fileB = p.file ? p.file->body : emptyFile;

    Bytes out;
    out.reserve(1 + 2 + langB.size() + 4 + textB.size()
                + 2 + nameB.size() + 2 + mimeB.size() + 4 + fileB.size());

    out.push_back(static_cast<std::uint8_t>(p.format));
    putU16(out, static_cast<std::uint16_t>(langB.size()));
    putBytes(out, reinterpret_cast<const std::uint8_t*>(langB.data()), langB.size());
    putU32(out, static_cast<std::uint32_t>(textB.size()));
    putBytes(out, reinterpret_cast<const std::uint8_t*>(textB.data()), textB.size());
    putU16(out, static_cast<std::uint16_t>(nameB.size()));
    putBytes(out, reinterpret_cast<const std::uint8_t*>(nameB.data()), nameB.size());
    putU16(out, static_cast<std::uint16_t>(mimeB.size()));
    putBytes(out, reinterpret_cast<const std::uint8_t*>(mimeB.data()), mimeB.size());
    putU32(out, static_cast<std::uint32_t>(fileB.size()));
    putBytes(out, fileB.data(), fileB.size());
    return out;
}

Payload unpackPayload(const Bytes& b) {
    if (b.empty()) {
        throw std::runtime_error("payload empty");
    }
    Payload p;
    std::size_t o = 0;
    p.format = static_cast<Format>(b[o++]);

    const auto langLen = readU16(b, o);
    if (o + langLen > b.size()) {
        throw std::runtime_error("payload truncated");
    }
    p.lang.assign(reinterpret_cast<const char*>(b.data() + o), langLen);
    o += langLen;

    const auto textLen = readU32(b, o);
    if (o + textLen > b.size()) {
        throw std::runtime_error("payload truncated");
    }
    p.text.assign(reinterpret_cast<const char*>(b.data() + o), textLen);
    o += textLen;

    const auto nameLen = readU16(b, o);
    if (o + nameLen > b.size()) {
        throw std::runtime_error("payload truncated");
    }
    std::string name(reinterpret_cast<const char*>(b.data() + o), nameLen);
    o += nameLen;

    const auto mimeLen = readU16(b, o);
    if (o + mimeLen > b.size()) {
        throw std::runtime_error("payload truncated");
    }
    std::string mime(reinterpret_cast<const char*>(b.data() + o), mimeLen);
    o += mimeLen;

    const auto fileLen = readU32(b, o);
    if (o + fileLen > b.size()) {
        throw std::runtime_error("payload truncated");
    }
    if (nameLen > 0 || mimeLen > 0 || fileLen > 0) {
        File f;
        f.name = std::move(name);
        f.mime = std::move(mime);
        f.body.assign(b.begin() + o, b.begin() + o + fileLen);
        p.file = std::move(f);
    }
    o += fileLen;
    return p;
}

}  // namespace blin
