#pragma once
// clang-format off
#include <Windows.h>
#include <WinInet.h>
#include <urlmon.h>
// clang-format on
#include <map>

#include "json.hpp"

#pragma comment(lib, "urlmon.lib")
#pragma comment(lib, "wininet.lib")

namespace networking {
    using errorable_json_result = std::pair<nlohmann::json, bool>;
    constexpr const char* err_json_data = "{\"error\": \"Unable to connect to server\"}";

    errorable_json_result get(const char* domain, const char* url);
} // namespace networking
