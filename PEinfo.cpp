#include "PEInfo.h"
#include <stdio.h>
#include <wincrypt.h>
#include <wintrust.h>
#include <softpub.h>

#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "wintrust.lib")

std::string PEInfoExtractor::ComputeSHA1(const wchar_t* path)
{
    HCRYPTPROV prov = 0;
    HCRYPTHASH hash = 0;
    HANDLE file = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (file == INVALID_HANDLE_VALUE) return "ERROR";

    std::string result = "ERROR";

    if (CryptAcquireContext(&prov, nullptr, nullptr, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT) &&
        CryptCreateHash(prov, CALG_SHA1, 0, 0, &hash))
    {
        BYTE buf[65536];
        DWORD read;
        while (ReadFile(file, buf, sizeof(buf), &read, nullptr) && read)
            CryptHashData(hash, buf, read, 0);

        BYTE hashval[20]{};
        DWORD len = sizeof(hashval);

        if (CryptGetHashParam(hash, HP_HASHVAL, hashval, &len, 0))
        {
            char hex[41]{};
            for (int i = 0; i < 20; ++i)
                sprintf_s(hex + i * 2, 3, "%02x", hashval[i]);
            result = hex;
        }
    }

    if (hash) CryptDestroyHash(hash);
    if (prov) CryptReleaseContext(prov, 0);
    CloseHandle(file);
    return result;
}

static void PrintSignatureInfo(const wchar_t* path)
{
    WINTRUST_DATA wd{};
    WINTRUST_FILE_INFO wfi{};
    GUID action = WINTRUST_ACTION_GENERIC_VERIFY_V2;

    wfi.cbStruct = sizeof(wfi);
    wfi.pcwszFilePath = path;

    wd.cbStruct = sizeof(wd);
    wd.dwUIChoice = WTD_UI_NONE;
    wd.fdwRevocationChecks = WTD_REVOKE_NONE;
    wd.dwUnionChoice = WTD_CHOICE_FILE;
    wd.pFile = &wfi;
    wd.dwStateAction = WTD_STATEACTION_VERIFY;

    LONG status = WinVerifyTrust(nullptr, &action, &wd);

    if (status == TRUST_E_NOSIGNATURE || status == TRUST_E_SUBJECT_FORM_UNKNOWN || status == TRUST_E_BAD_DIGEST)
    {
        printf(" [+] Digital Signature : Not found\n\n");
        wd.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(nullptr, &action, &wd);
        return;
    }

    if (status != 0)
    {
        printf(" [+] Digital Signature : Invalid\n\n");
        wd.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(nullptr, &action, &wd);
        return;
    }

    HCERTSTORE hStore = nullptr;
    HCRYPTMSG hMsg = nullptr;

    if (!CryptQueryObject(CERT_QUERY_OBJECT_FILE, path,
        CERT_QUERY_CONTENT_FLAG_PKCS7_SIGNED_EMBED,
        CERT_QUERY_FORMAT_FLAG_BINARY, 0, nullptr, nullptr, nullptr,
        &hStore, &hMsg, nullptr))
    {
        printf(" [+] Digital Signature : Present (details unavailable)\n\n");
        wd.dwStateAction = WTD_STATEACTION_CLOSE;
        WinVerifyTrust(nullptr, &action, &wd);
        return;
    }

    DWORD dwSignerInfo = 0;
    CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, nullptr, &dwSignerInfo);
    PCMSG_SIGNER_INFO pSignerInfo = (PCMSG_SIGNER_INFO)malloc(dwSignerInfo);
    CryptMsgGetParam(hMsg, CMSG_SIGNER_INFO_PARAM, 0, pSignerInfo, &dwSignerInfo);

    CERT_INFO CertInfo{};
    CertInfo.Issuer = pSignerInfo->Issuer;
    CertInfo.SerialNumber = pSignerInfo->SerialNumber;

    PCCERT_CONTEXT pCert = CertFindCertificateInStore(hStore,
        X509_ASN_ENCODING | PKCS_7_ASN_ENCODING, 0, CERT_FIND_SUBJECT_CERT, &CertInfo, nullptr);

    char name[512]{};

    if (pCert)
    {
        CertGetNameStringA(pCert, CERT_NAME_FRIENDLY_DISPLAY_TYPE, 0, nullptr, name, sizeof(name));
        CertFreeCertificateContext(pCert);
    }

    printf(" [+] Digital Signature : %s / %s\n\n", name, pSignerInfo->HashAlgorithm.pszObjId);

    free(pSignerInfo);
    if (hMsg) CryptMsgClose(hMsg);
    if (hStore) CertCloseStore(hStore, 0);

    wd.dwStateAction = WTD_STATEACTION_CLOSE;
    WinVerifyTrust(nullptr, &action, &wd);
}

bool PEInfoExtractor::ExtractAndPrint(const wchar_t* path)
{
    SetConsoleTitleW(L"Information Extractor");

    HANDLE hFile = CreateFileW(path, GENERIC_READ, FILE_SHARE_READ, nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    LARGE_INTEGER size{};
    if (!GetFileSizeEx(hFile, &size))
    {
        CloseHandle(hFile);
        return false;
    }

    HANDLE hMap = CreateFileMappingW(hFile, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (!hMap)
    {
        CloseHandle(hFile);
        return false;
    }

    BYTE* base = (BYTE*)MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);
    if (!base)
    {
        CloseHandle(hMap);
        CloseHandle(hFile);
        return false;
    }

    bool success = false;

    const IMAGE_DOS_HEADER* dos = (IMAGE_DOS_HEADER*)base;

    if (dos->e_magic == IMAGE_DOS_SIGNATURE)
    {
        const IMAGE_NT_HEADERS* nt = (IMAGE_NT_HEADERS*)(base + dos->e_lfanew);

        if (nt->Signature == IMAGE_NT_SIGNATURE)
        {
            ULONGLONG t = ((ULONGLONG)nt->FileHeader.TimeDateStamp * 10000000ULL) + 116444736000000000ULL;
            FILETIME ft = { (DWORD)t, (DWORD)(t >> 32) };
            SYSTEMTIME st{};
            FileTimeToSystemTime(&ft, &st);

            const wchar_t* fname = wcsrchr(path, L'\\');
            fname = fname ? fname + 1 : path;

            printf("\n [+] File Name         : %ls\n", fname);
            printf(" [+] File Size         : %lld bytes\n", size.QuadPart);
            printf(" [+] SHA1              : %s\n", ComputeSHA1(path).c_str());
            printf(" [+] Image Size        : 0x%08X\n", nt->OptionalHeader.SizeOfImage);
            printf(" [+] Compile Date      : %04d/%02d/%02d %02d:%02d:%02d\n",
                st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);

            WORD ch = nt->FileHeader.Characteristics;
            printf(" [+] Characteristics   : ");
            if (ch & IMAGE_FILE_EXECUTABLE_IMAGE) printf("EXECUTABLE ");
            if (ch & IMAGE_FILE_DLL) printf("DLL ");
            if (ch & IMAGE_FILE_SYSTEM) printf("SYSTEM ");
            if (ch & IMAGE_FILE_LARGE_ADDRESS_AWARE) printf("LARGE_ADDRESS_AWARE ");
            if (ch & IMAGE_FILE_DEBUG_STRIPPED) printf("DEBUG_STRIPPED ");
            if (ch & IMAGE_FILE_REMOVABLE_RUN_FROM_SWAP) printf("REMOVABLE_SWAP ");
            if (ch & IMAGE_FILE_NET_RUN_FROM_SWAP) printf("NET_SWAP ");
            if (ch & IMAGE_FILE_UP_SYSTEM_ONLY) printf("UP_SYSTEM ");
            if (ch & IMAGE_FILE_BYTES_REVERSED_LO) printf("BYTE_REVERSED_LO ");
            printf("\n");

            bool packed = false;

            DWORD ep = nt->OptionalHeader.AddressOfEntryPoint;
            DWORD imageBase = nt->OptionalHeader.ImageBase;
            DWORD epVA = ep + imageBase;

            const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);
            const IMAGE_SECTION_HEADER* textSec = nullptr;

            for (int i = 0; i < nt->FileHeader.NumberOfSections; i++)
            {
                if (memcmp(sec[i].Name, ".text", 5) == 0)
                {
                    textSec = &sec[i];
                    break;
                }
            }

            if (textSec)
            {
                DWORD textStart = textSec->VirtualAddress + imageBase;
                DWORD textEnd = textStart + textSec->Misc.VirtualSize;

                if (epVA < textStart || epVA > textEnd) packed = true;
                if (textSec->Misc.VirtualSize < 0x1000) packed = true;
            }

            if (nt->FileHeader.NumberOfSections <= 2) packed = true;
            if (nt->OptionalHeader.SizeOfHeaders > 0x3000) packed = true;

            printf(" [+] Packing Heuristic : %s\n", packed ? "Likely packed" : "Normal");

            PrintSignatureInfo(path);

            success = true;
        }
    }

    UnmapViewOfFile(base);
    CloseHandle(hMap);
    CloseHandle(hFile);
    return success;
}
