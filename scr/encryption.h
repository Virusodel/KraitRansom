#pragma once
#include <vector>
#include <string>
#include <cstdint>

class Encryption {
public:
    static void Initialize(const std::vector<uint8_t>& key);
    static void EncryptFile(const std::string& filePath);
    static void DecryptFile(const std::string& filePath);
    static std::vector<uint8_t> EncryptData(const std::vector<uint8_t>& data);
    static std::vector<uint8_t> DecryptData(const std::vector<uint8_t>& data);
};
