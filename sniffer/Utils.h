#pragma once

#include <unordered_map>
#include <string>

inline const char * unwrap_or_default(const std::unordered_map<std::string, std::string> & map, const char * key, const char * def = "") {
    return map.count(key) > 0 ? map.at(key).c_str() : def;
}
