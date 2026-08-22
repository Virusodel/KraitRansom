#include "utils.h"
#include <windows.h>
#include <vector>

std::vector<uint8_t> StringToBytes(const std::string& str) {
    std::vector<uint8_t> bytes;
    for (char c : str) {
        bytes.push_back(static_cast<uint8_t>(c));
    }
    return bytes;
}

std::string BytesToString(const std::vector<uint8_t>& bytes) {
    std::string str;
    for (uint8_t b : bytes) {
        str.push_back(static_cast<char>(b));
    }
    return str;
}
