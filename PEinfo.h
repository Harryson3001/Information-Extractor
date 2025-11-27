#pragma once
#include <windows.h>
#include <string>

class PEInfoExtractor {
public:
    static bool ExtractAndPrint(const wchar_t* filePath);

private:
    static std::string ComputeSHA1(const wchar_t* path);
    static void PrintHeader();
};