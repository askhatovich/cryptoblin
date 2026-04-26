#include "config.h"
#include "crypto.h"
#include "http.h"
#include "payload.h"
#include "pow_solve.h"
#include "url.h"

#include "util.h"

#include <array>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>
#include <stdexcept>
#include <string>
#include <vector>

#ifdef _WIN32
#  include <io.h>
#  define BLIN_ISATTY _isatty
#  define BLIN_FILENO _fileno
#else
#  include <unistd.h>
#  define BLIN_ISATTY isatty
#  define BLIN_FILENO fileno
#endif

namespace {

constexpr const char* kHelp = R"(blin — CLI client for cryptoblin (zero-knowledge note sharing)

USAGE
  blin send   [-f text|markdown|highlight] [-l LANG] [-p PASSWORD] [-b] [FILE]
  blin get    URL [-p PASSWORD] [-o OUTFILE]
  blin delete URL
  blin --help

COMMANDS
  send     Encrypt and upload a note. Reads body text from stdin (e.g.
           via a pipe). If FILE is given as the last positional argument,
           it is attached. Both stdin text and FILE may be present at once.
           On success prints the share URL on stdout and the delete URL on
           stderr.

  get      Fetch and decrypt a note from URL. Text is printed to stdout;
           an attached file is saved to the current directory using its
           original name (override with -o).

  delete   Delete a note using a creator-only delete URL (the one printed
           on stderr after `send`).

OPTIONS
  -f FMT       send: format of the text body. One of: text (default),
               markdown, highlight (server-side syntax highlighting).
  -l LANG      send: language hint for highlight format (e.g. python).
  -p PASSWORD  Optional password. Without it, send creates a non-password
               note; for get the URL itself indicates whether a password
               is required.
  -b           send: burn-after-read. The note destroys itself on first open.
  -o OUTFILE   get:  save the attached file (or text) to OUTFILE.

CONFIG
  Server URL is read from $HOME/.config/askhatovich/cryptoblin/config.conf
  (single line: SERVER=https://example.com). Default is https://paste.dotcpp.ru.

OUTPUT FORMAT
  stdout carries the data product of each command (the share URL on send,
  the decrypted text body on get, nothing on delete). stderr carries
  status as one `key: value` line per record field, plus free-form notes
  prefixed with `blin:` and fatal errors prefixed with `blin: error:`.
  Both streams are line-oriented and easy to parse.

  Send fields: id, size, ttl, expires_at, burn, password, delete.
  Get fields:  burned, views, created_at, expires_at, format, language,
               text_bytes, [text_path], [file_name, file_mime,
               file_bytes, file_path].
  Delete fields: id, status.

EXAMPLES
  echo "secret" | blin send
  blin send -b README.md
  echo '#include <stdio.h>' | blin send -f highlight -l c hello.c
  URL=$(echo "hi" | blin send 2>/dev/null)        # capture URL only
  blin get "$URL" 2>/tmp/meta                     # body to stdout, meta to file
  blin delete https://paste.dotcpp.ru/#del:abcd1234:AAA…
)";

// All non-data output goes to stderr and uses one of two prefixes so the
// stream is both grep-friendly and human-readable:
//   "blin: " + free-form one-liner status (progress, info)
//   "<key>: " + value (machine-parseable record fields)
// `error: <msg>` is reserved for fatal errors.
void die(const std::string& msg) {
    std::cerr << "blin: error: " << msg << "\n";
    std::exit(1);
}

void info(const std::string& msg) {
    std::cerr << "blin: " << msg << "\n";
}

// Print a "key: value" record line on stderr. Keys are short snake_case,
// values are unquoted free-form text up to end of line.
void field(const std::string& key, const std::string& value) {
    std::cerr << key << ": " << value << "\n";
}

blin::Bytes readAllStdin() {
    blin::Bytes out;
    if (BLIN_ISATTY(BLIN_FILENO(stdin))) {
        return out;  // no piped input
    }
    std::array<char, 8192> buf{};
    while (true) {
        const auto n = std::fread(buf.data(), 1, buf.size(), stdin);
        if (n == 0) break;
        out.insert(out.end(), buf.begin(), buf.begin() + n);
    }
    return out;
}

blin::Bytes readFile(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        throw std::runtime_error("cannot open file: " + path);
    }
    std::ostringstream ss;
    ss << f.rdbuf();
    const auto& s = ss.str();
    return blin::Bytes(s.begin(), s.end());
}

std::string readPasswordPrompt(const char* prompt) {
    std::cerr << prompt << std::flush;
    std::string s;
    std::getline(std::cin, s);
    return s;
}

std::string filenameOf(const std::string& path) {
    const auto slash = path.find_last_of('/');
    return (slash == std::string::npos) ? path : path.substr(slash + 1);
}

// Sanitise an attacker-controlled filename before writing it to the user's
// FS. Strips any directory components and drops the path entirely if what
// is left is empty, ".", or ".." — preventing a malicious sender from
// writing outside CWD via e.g. file_name="../../etc/passwd".
std::string safeBasename(const std::string& name) {
    std::string s = name;
    const auto slash = s.find_last_of("/\\");
    if (slash != std::string::npos) {
        s = s.substr(slash + 1);
    }
    if (s.empty() || s == "." || s == "..") {
        return "blin-attachment";
    }
    return s;
}

std::string mimeFor(const std::string& filename) {
    const auto dot = filename.find_last_of('.');
    if (dot == std::string::npos) return "application/octet-stream";
    std::string ext = filename.substr(dot + 1);
    for (auto& c : ext) c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
    if (ext == "txt" || ext == "md")     return "text/plain";
    if (ext == "json")                    return "application/json";
    if (ext == "png")                     return "image/png";
    if (ext == "jpg" || ext == "jpeg")    return "image/jpeg";
    if (ext == "gif")                     return "image/gif";
    if (ext == "pdf")                     return "application/pdf";
    return "application/octet-stream";
}

// --- Tiny JSON helpers (we control the shape of every response).
std::string jsonStr(const std::string& s, const char* key) {
    const std::string needle = std::string("\"") + key + "\":";
    auto p = s.find(needle);
    if (p == std::string::npos) return {};
    p += needle.size();
    while (p < s.size() && (s[p] == ' ' || s[p] == '\t')) ++p;
    if (p >= s.size() || s[p] != '"') return {};
    ++p;
    std::string out;
    while (p < s.size() && s[p] != '"') {
        if (s[p] == '\\' && p + 1 < s.size()) {
            ++p;
        }
        out.push_back(s[p++]);
    }
    return out;
}

long long jsonInt(const std::string& s, const char* key) {
    const std::string needle = std::string("\"") + key + "\":";
    auto p = s.find(needle);
    if (p == std::string::npos) return 0;
    p += needle.size();
    while (p < s.size() && (s[p] == ' ' || s[p] == '\t')) ++p;
    long long sign = 1;
    if (p < s.size() && s[p] == '-') { sign = -1; ++p; }
    long long v = 0;
    while (p < s.size() && std::isdigit(static_cast<unsigned char>(s[p]))) {
        v = v * 10 + (s[p++] - '0');
    }
    return sign * v;
}

unsigned jsonUint(const std::string& s, const char* key) {
    return static_cast<unsigned>(jsonInt(s, key));
}

// Parse decimal int from a header value (returns 0 on failure).
long long headerInt(const blin::Response& r, const std::string& name) {
    const auto it = r.headers.find(name);
    if (it == r.headers.end()) return 0;
    try {
        return std::stoll(it->second);
    } catch (...) {
        return 0;
    }
}

// ----- send -----------------------------------------------------------------
int cmdSend(int argc, char** argv) {
    blin::Format fmt = blin::Format::Text;
    std::string  lang;
    std::string  password;
    bool         burn = false;
    std::string  filePath;

    for (int i = 0; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "-f" && i + 1 < argc) {
            const std::string v = argv[++i];
            if      (v == "text")      fmt = blin::Format::Text;
            else if (v == "markdown")  fmt = blin::Format::Markdown;
            else if (v == "highlight") fmt = blin::Format::Code;
            else die("unknown format: " + v);
        } else if (a == "-l" && i + 1 < argc) {
            lang = argv[++i];
        } else if (a == "-p" && i + 1 < argc) {
            password = argv[++i];
        } else if (a == "-b") {
            burn = true;
        } else if (a == "--help" || a == "-h") {
            std::cout << kHelp;
            return 0;
        } else if (!a.empty() && a[0] == '-') {
            die("unknown option: " + a);
        } else {
            filePath = a;
        }
    }

    blin::Bytes stdinBytes = readAllStdin();
    blin::Bytes fileBytes;
    if (!filePath.empty()) {
        fileBytes = readFile(filePath);
    }
    if (stdinBytes.empty() && fileBytes.empty()) {
        die("nothing to send: pipe text in or pass a FILE (use --help)");
    }

    blin::cryptoInit();

    const std::string seed = blin::randomSeed();
    const auto key = blin::deriveKey(seed, password);

    blin::Payload p;
    p.format = fmt;
    if (fmt == blin::Format::Code) p.lang = lang;
    p.text.assign(stdinBytes.begin(), stdinBytes.end());
    if (!fileBytes.empty()) {
        blin::File f;
        f.name = filenameOf(filePath);
        f.mime = mimeFor(f.name);
        f.body = std::move(fileBytes);
        p.file = std::move(f);
    }

    const auto payloadBytes = blin::packPayload(p);
    const auto envelope     = blin::sealEnvelope(payloadBytes, key);
    const auto challenge    = blin::makeChallenge(key, burn);

    blin::Bytes wire;
    wire.reserve(challenge.plaintext.size() + challenge.nonce.size()
                 + challenge.ciphertext.size() + envelope.size());
    wire.insert(wire.end(), challenge.plaintext.begin(),  challenge.plaintext.end());
    wire.insert(wire.end(), challenge.nonce.begin(),      challenge.nonce.end());
    wire.insert(wire.end(), challenge.ciphertext.begin(), challenge.ciphertext.end());
    wire.insert(wire.end(), envelope.begin(),             envelope.end());

    const auto serverUrlStr = blin::loadServer();
    const auto server = blin::parseServerUrl(serverUrlStr);

    // Captcha + PoW.
    blin::Request capReq{};
    capReq.method = "GET";
    capReq.path   = "/api/captcha";
    const auto capRes = blin::httpDo(server, capReq);
    if (capRes.status != 200) {
        die("captcha request failed: HTTP " + std::to_string(capRes.status));
    }
    const std::string capBody(capRes.body.begin(), capRes.body.end());
    const auto powToken = jsonStr(capBody, "token");
    const auto powDiff  = jsonUint(capBody, "difficulty");
    if (powToken.empty()) {
        die("captcha response missing token");
    }
    info("solving captcha (" + std::to_string(powDiff) + " bits)");
    const auto powNonce = blin::solvePow(powToken, powDiff);

    blin::Request createReq{};
    createReq.method = "POST";
    createReq.path   = "/api/pastes";
    createReq.headers["Content-Type"] = "application/octet-stream";
    createReq.headers["X-Pow-Token"]  = powToken;
    createReq.headers["X-Pow-Nonce"]  = powNonce;
    createReq.body = std::move(wire);
    const auto createRes = blin::httpDo(server, createReq);
    if (createRes.status != 201) {
        const std::string body(createRes.body.begin(), createRes.body.end());
        die("create failed: HTTP " + std::to_string(createRes.status) + " " + body);
    }

    const std::string body(createRes.body.begin(), createRes.body.end());
    const auto id          = jsonStr(body, "id");
    const auto deleteToken = jsonStr(body, "delete_token");
    const auto sizeOnWire  = jsonInt(body, "size");
    const auto expiresAt   = jsonInt(body, "expires_at");
    const auto ttl         = jsonInt(body, "ttl_seconds");
    if (id.empty() || deleteToken.empty()) {
        die("create response missing id or delete_token");
    }

    const bool hasPassword = !password.empty();
    const auto shareUrl  = blin::buildViewUrl  (serverUrlStr, id, seed, hasPassword);
    const auto deleteUrl = blin::buildDeleteUrl(serverUrlStr, id, deleteToken);

    // Machine-parseable record on stderr: one `key: value` per line.
    field("id",         id);
    field("size",       std::to_string(sizeOnWire));
    field("ttl",        std::to_string(ttl));
    field("expires_at", std::to_string(expiresAt));
    field("burn",       burn ? "true" : "false");
    field("password",   hasPassword ? "true" : "false");
    field("delete",     deleteUrl);
    // The share URL is the data product of `send` — print it on stdout so a
    // shell pipe can capture exactly that one line.
    std::cout << shareUrl << "\n";
    return 0;
}

// ----- get ------------------------------------------------------------------
int cmdGet(int argc, char** argv) {
    std::string urlArg;
    std::string password;
    std::string outFile;
    for (int i = 0; i < argc; ++i) {
        const std::string a = argv[i];
        if      (a == "-p" && i + 1 < argc) password = argv[++i];
        else if (a == "-o" && i + 1 < argc) outFile  = argv[++i];
        else if (a == "--help" || a == "-h") { std::cout << kHelp; return 0; }
        else if (!a.empty() && a[0] == '-') die("unknown option: " + a);
        else                                 urlArg = a;
    }
    if (urlArg.empty()) {
        die("get requires a paste URL");
    }
    const auto pu = blin::parsePasteUrl(urlArg);
    if (pu.kind != blin::PasteUrl::Kind::View) {
        die("not a view URL");
    }
    if (pu.hasPassword && password.empty()) {
        password = readPasswordPrompt("password: ");
    }

    const auto serverUrlStr = blin::loadServer();
    const auto server = blin::parseServerUrl(serverUrlStr);

    blin::cryptoInit();
    const auto key = blin::deriveKey(pu.seed, password);

    // /open
    blin::Request openReq{};
    openReq.method = "POST";
    openReq.path   = "/api/pastes/" + pu.id + "/open";
    const auto openRes = blin::httpDo(server, openReq);
    if (openRes.status != 200) {
        die("open failed: HTTP " + std::to_string(openRes.status));
    }
    const std::string ob(openRes.body.begin(), openRes.body.end());
    const auto token   = jsonStr(ob, "token");
    const auto nonceB64= jsonStr(ob, "nonce");
    const auto ctB64   = jsonStr(ob, "ciphertext");
    if (token.empty() || nonceB64.empty() || ctB64.empty()) {
        die("open response malformed");
    }

    bool ok = false;
    const auto nonce = util::base64Decode(nonceB64, &ok);
    if (!ok) die("bad nonce b64");
    const auto cipher = util::base64Decode(ctB64, &ok);
    if (!ok) die("bad cipher b64");

    blin::Bytes challengePt;
    try {
        challengePt = blin::solveChallenge(nonce, cipher, key);
    } catch (const std::exception& e) {
        die(std::string("decrypt failed (wrong key/password): ") + e.what());
    }

    // /blob
    const auto ptB64 = util::base64Encode(challengePt);
    const std::string body =
        "{\"token\":\"" + token + "\",\"plaintext\":\"" + ptB64 + "\"}";
    blin::Request blobReq{};
    blobReq.method = "POST";
    blobReq.path   = "/api/pastes/" + pu.id + "/blob";
    blobReq.headers["Content-Type"] = "application/json";
    blobReq.body.assign(body.begin(), body.end());
    const auto blobRes = blin::httpDo(server, blobReq);
    if (blobRes.status != 200) {
        const std::string bb(blobRes.body.begin(), blobRes.body.end());
        die("blob failed: HTTP " + std::to_string(blobRes.status) + " " + bb);
    }

    blin::Bytes envelope = blobRes.body;
    blin::Bytes plain;
    try {
        plain = blin::openEnvelope(envelope, key);
    } catch (const std::exception& e) {
        die(std::string("envelope decrypt failed: ") + e.what());
    }
    const auto p = blin::unpackPayload(plain);

    const bool burned = blobRes.headers.count("x-burned") &&
                        blobRes.headers.at("x-burned") == "1";
    const auto views     = headerInt(blobRes, "x-view-count");
    const auto createdAt = headerInt(blobRes, "x-created-at");
    const auto expiresAt = headerInt(blobRes, "x-expires-at");

    // Format detection.
    const char* formatStr = "text";
    if (p.format == blin::Format::Markdown) formatStr = "markdown";
    if (p.format == blin::Format::Code)     formatStr = "highlight";

    // Status record on stderr: one `key: value` per line. Emit BEFORE writing
    // the body to stdout so the human-visible record is not buried by a
    // multi-megabyte attachment dump.
    field("burned",     burned ? "true" : "false");
    field("views",      std::to_string(views));
    field("created_at", std::to_string(createdAt));
    field("expires_at", std::to_string(expiresAt));
    field("format",     formatStr);
    if (p.format == blin::Format::Code && !p.lang.empty()) {
        field("language", p.lang);
    }
    field("text_bytes", std::to_string(p.text.size()));
    if (p.file) {
        field("file_name",  p.file->name);
        field("file_mime",  p.file->mime);
        field("file_bytes", std::to_string(p.file->body.size()));
    }

    // Decide where the text goes:
    //   - if -o is given and there is no attached file, write text to OUTFILE
    //   - otherwise write text body verbatim to stdout (no added newline)
    if (!p.text.empty()) {
        if (!outFile.empty() && !p.file) {
            std::ofstream f(outFile, std::ios::binary);
            if (!f) die("cannot write " + outFile);
            f.write(p.text.data(), static_cast<std::streamsize>(p.text.size()));
            field("text_path", outFile);
        } else {
            std::fwrite(p.text.data(), 1, p.text.size(), stdout);
        }
    }

    // Save attached file. With -o the user override wins; otherwise use the
    // sender-provided filename, but only its basename — never a path.
    // Refuse to overwrite an existing file unless -o is set explicitly.
    if (p.file) {
        const bool userPath = !outFile.empty();
        const std::string out = userPath ? outFile : safeBasename(p.file->name);
        if (!userPath) {
            std::ifstream probe(out);
            if (probe.good()) {
                die("refusing to overwrite existing file: " + out
                    + " (pass -o PATH to override)");
            }
        }
        std::ofstream f(out, std::ios::binary);
        if (!f) die("cannot write " + out);
        f.write(reinterpret_cast<const char*>(p.file->body.data()),
                static_cast<std::streamsize>(p.file->body.size()));
        field("file_path", out);
    }
    return 0;
}

// ----- delete ---------------------------------------------------------------
int cmdDelete(int argc, char** argv) {
    std::string urlArg;
    for (int i = 0; i < argc; ++i) {
        const std::string a = argv[i];
        if (a == "--help" || a == "-h") { std::cout << kHelp; return 0; }
        if (!a.empty() && a[0] == '-')   die("unknown option: " + a);
        urlArg = a;
    }
    if (urlArg.empty()) {
        die("delete requires a delete URL");
    }
    const auto pu = blin::parsePasteUrl(urlArg);
    if (pu.kind != blin::PasteUrl::Kind::Delete) {
        die("not a delete URL (expected #del:<id>:<token>)");
    }

    const auto server = blin::parseServerUrl(blin::loadServer());
    blin::Request req{};
    req.method = "DELETE";
    req.path   = "/api/pastes/" + pu.id;
    req.headers["X-Delete-Token"] = pu.deleteToken;
    const auto res = blin::httpDo(server, req);
    if (res.status == 200) {
        field("id",     pu.id);
        field("status", "deleted");
        return 0;
    }
    const std::string body(res.body.begin(), res.body.end());
    die("delete failed: HTTP " + std::to_string(res.status) + " " + body);
    return 1;
}

}  // namespace

int main(int argc, char** argv) {
    if (argc < 2) {
        std::cerr << kHelp;
        return 1;
    }
    const std::string sub = argv[1];
    if (sub == "--help" || sub == "-h" || sub == "help") {
        std::cout << kHelp;
        return 0;
    }
    try {
        if (sub == "send")   return cmdSend(argc - 2, argv + 2);
        if (sub == "get")    return cmdGet(argc - 2, argv + 2);
        if (sub == "delete") return cmdDelete(argc - 2, argv + 2);
    } catch (const std::exception& e) {
        die(e.what());
    }
    die("unknown command: " + sub);
    return 1;
}
