#pragma once
#include <string>
#include <vector>
#include <cstdint>

std::vector<uint8_t> StringToBytes(const std::string& str);
std::string BytesToString(const std::vector<uint8_t>& bytes);
