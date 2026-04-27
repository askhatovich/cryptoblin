#pragma once

#include <string>

namespace blin {

// Default upstream. Overridden by SERVER= in
// $HOME/.config/askhatovich/cryptoblin.conf.
inline constexpr const char* kDefaultServer = "https://paste.dotcpp.ru";

std::string loadServer();

}  // namespace blin
