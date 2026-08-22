#include "keygen.h"
#include <windows.h>
#include <iphlpapi.h>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <intrin.h>

#pragma comment(lib, "iphlpapi.lib")

std::string KeyGen::GetMachineID() {
    std::stringstream ss;
    
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 1);
    ss << std::hex << cpuInfo[0] << cpuInfo[3];
    
    DWORD serial;
    GetVolumeInformationA("C:\\", NULL, 0, &serial, NULL, NULL, NULL, 0);
    ss << std::hex << serial;
    
    PIP_ADAPTER_INFO pAdapterInfo = (IP_ADAPTER_INFO*)malloc(sizeof(IP_ADAPTER_INFO));
    ULONG ulOutBufLen = sizeof(IP_ADAPTER_INFO);
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == ERROR_BUFFER_OVERFLOW) {
        free(pAdapterInfo);
        pAdapterInfo = (IP_ADAPTER_INFO*)malloc(ulOutBufLen);
    }
    if (GetAdaptersInfo(pAdapterInfo, &ulOutBufLen) == NO_ERROR) {
        PIP_ADAPTER_INFO pAdapter = pAdapterInfo;
        while (pAdapter) {
            for (int i = 0; i < pAdapter->AddressLength; i++) {
                ss << std::hex << std::setw(2) << std::setfill('0') << (int)pAdapter->Address[i];
            }
            pAdapter = pAdapter->Next;
        }
    }
    free(pAdapterInfo);
    
    return ss.str();
}

std::vector<uint8_t> KeyGen::SHA256(const std::vector<uint8_t>& data) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    std::vector<uint8_t> hash(32);
    
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        return hash;
    }
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) {
        CryptReleaseContext(hProv, 0);
        return hash;
    }
    if (!CryptHashData(hHash, data.data(), data.size(), 0)) {
        CryptDestroyHash(hHash);
        CryptReleaseContext(hProv, 0);
        return hash;
    }
    DWORD hashLen = 32;
    CryptGetHashParam(hHash, HP_HASHVAL, hash.data(), &hashLen, 0);
    
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return hash;
}

std::vector<uint8_t> KeyGen::GenerateMasterKey() {
    std::string machineID = GetMachineID();
    std::vector<uint8_t> data(machineID.begin(), machineID.end());
    
    SYSTEMTIME st;
    GetSystemTime(&st);
    std::string salt = std::to_string(st.wYear) + std::to_string(st.wMonth) + 
                       std::to_string(st.wDay) + std::to_string(st.wHour);
    data.insert(data.end(), salt.begin(), salt.end());
    
    LARGE_INTEGER perf;
    QueryPerformanceCounter(&perf);
    std::string perfStr = std::to_string(perf.QuadPart);
    data.insert(data.end(), perfStr.begin(), perfStr.end());
    
    return SHA256(data);
}

std::string KeyGen::GeneratePersonalKey(const std::vector<uint8_t>& masterKey) {
    std::stringstream ss;
    for (int i = 0; i < 16; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)masterKey[i];
        if (i % 4 == 3 && i < 15) ss << "-";
    }
    return ss.str();
}

std::vector<uint8_t> KeyGen::DeriveChaChaKey(const std::string& personalKey) {
    std::string clean;
    for (char c : personalKey) {
        if (c != '-') clean += c;
    }
    
    std::vector<uint8_t> keyData;
    for (size_t i = 0; i < clean.length(); i += 2) {
        std::string byteStr = clean.substr(i, 2);
        uint8_t byte = (uint8_t)strtol(byteStr.c_str(), NULL, 16);
        keyData.push_back(byte);
    }
    
    while (keyData.size() < 32) {
        keyData.push_back(0);
    }
    
    return SHA256(keyData);
}
