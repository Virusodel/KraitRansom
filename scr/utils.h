#pragma once
#include <string>
#include <vector>

std::vector<uint8_t> StringToBytes(const std::string& str);
std::string BytesToString(const std::vector<uint8_t>& bytes);
