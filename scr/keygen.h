#pragma once
#include <string>
#include <vector>
#include <cstdint>

class KeyGen {
public:
    static std::vector<uint8_t> GenerateMasterKey();
    static std::string GeneratePersonalKey(const std::vector<uint8_t>& masterKey);
    static std::vector<uint8_t> DeriveChaChaKey(const std::string& personalKey);
private:
    static std::string GetMachineID();
    static std::vector<uint8_t> SHA256(const std::vector<uint8_t>& data);
};
