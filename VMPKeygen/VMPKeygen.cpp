// VMPKeygen.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include <Windows.h>
#include <cassert>
#include "KeyGenAPI.h"

// KeyPair exported
VMProtectAlgorithms g_Algorithm = ALGORITHM_RSA;
size_t g_nBits = 2048;
byte g_vPrivate[256] = {
    9, 129,  84, 251, 198,  14,  47, 144,  27,  85, 117, 188, 144,  31, 205,  34,
    164, 240,  45, 189,   4, 100, 209, 130,  40, 246, 139, 151, 153, 243, 195, 143,
    238, 247, 228, 100,  72, 247, 181,  39, 138, 253,  24, 177, 141, 198,  36,  70,
    250, 117,  70, 138,  66, 137, 181,  92, 138, 159, 254, 250, 154,  65,  37, 206,
    17, 224, 112, 183, 105,  20, 196,  61, 208,  96, 178, 146,  55, 215, 170,  36,
    126, 165,  58,  22,   5,  42, 189, 233,  68, 165, 187,  88, 239,  53,  44,  68,
    42,  34, 149,  22, 158, 129,  94, 122,  30,  17,  29,  12, 239,  48, 111,  39,
    139,  77, 117, 227, 188, 168, 242, 228, 228, 134,  94, 203,  12, 196, 122, 125,
    148, 214,  97,  95, 235, 232, 120,  50, 145, 220, 235, 183, 199,  57, 210, 173,
    37, 100, 126, 119, 160, 173, 229,  75, 214, 251, 205, 201, 101, 178, 200, 174,
    174,  27,  53, 174,  39, 246,  21,  67, 225, 255, 153,  99, 193, 170,   0, 188,
    115, 114, 183, 210,  55, 187,  58, 154, 130,  14, 154, 227, 132, 249, 251,  65,
    174,  10,  72, 110, 102, 228,   9, 146,  74, 242, 178,  36,  55, 111, 157,  28,
    193, 137, 245,  32, 237, 145, 248, 245,  42,   0, 200, 163,  93, 122,  54, 137,
    178, 143, 208,  87, 185, 157, 152, 146, 177,  56,  66, 142, 140,  29, 236, 201,
    60, 250, 172,  81, 145, 146,   8,  44, 137, 208, 169,  35, 107, 160, 165,  85 };

byte g_vModulus[256] = {
    143, 200, 154, 163, 233, 199, 200, 212,  46,  16,  49, 192, 241, 207, 144,  28,
    245,  37, 151,  48,  95,  31,  87,  46, 249,  55, 139, 215,  82,   1, 175,  83,
    156, 154, 107,  65, 118,  37, 135,  61,   4,  97, 122,  21, 212, 201, 217,  62,
    196,   2, 198, 236,  61,  84, 238, 247, 193, 162, 112, 153,  58, 206, 192, 224,
    132,  69,  12, 215, 199,  73,  36,  12, 113, 243, 211,  37, 162,  86, 144,  62,
    113, 156,  62,  60,  12, 116,  28, 244,  47, 144, 233, 233,  42, 102, 245, 181,
    131, 109,  76,   7, 107, 206,  78,  66, 250, 170, 137,  37, 144, 148, 205, 251,
    1,  39,  10,   6, 242,  32,  14, 255, 194,  68, 173, 235, 241, 111, 184, 191,
    185,  65, 222, 156, 119,   1,  51, 186, 188, 129, 154, 123, 158, 142,  59,  91,
    86,  86, 183, 211,  97, 115,  49, 183, 104,  87,  35,  92, 122,  52,  31, 211,
    109,  22, 168, 150,  53, 169,  74,  10,  97, 160,  65,  84, 217,  22,   4,  88,
    0,  23,  81, 111,  79, 149, 155, 159, 105, 156,  13, 185,  71, 120, 138, 235,
    176, 226,   4, 143,  50, 196, 219, 246, 181, 142,  93,  42,  68, 208, 120, 130,
    207, 131, 146,  98, 171, 131,  92,  63, 242, 155, 239, 128,  70, 139, 224, 172,
    9, 102,   6, 126,  23,  93, 136, 222,  48,  81,  16, 194, 196, 105, 192,  11,
    253, 162,  11, 171,  80, 251, 201,  70, 102,  19,  12,  60, 146,  71,  42, 247 };

byte g_vProductCode[8] = { 16, 198,  54, 222, 236, 224,  25, 224 };


#define LICENSE_FILE_NAME L"license.lic"
#define INFO_FILE_NAME L"info.txt"

int wmain(int argc, wchar_t* argv[])
{
    VMProtectProductInfo pi;
    pi.algorithm = g_Algorithm;
    pi.nBits = g_nBits;
    pi.nModulusSize = sizeof(g_vModulus);
    pi.pModulus = g_vModulus;
    pi.nPrivateSize = sizeof(g_vPrivate);
    pi.pPrivate = g_vPrivate;
    pi.nProductCodeSize = sizeof(g_vProductCode);
    pi.pProductCode = g_vProductCode;

    VMProtectSerialNumberInfo si = { 0 };
    si.flags = HAS_USER_NAME | HAS_EMAIL | HAS_HARDWARE_ID | HAS_EXP_DATE | HAS_MAX_BUILD_DATE | HAS_TIME_LIMIT;

    wchar_t inName[MAX_PATH * 2] = { 0 };
    wprintf(TEXT("User Name: "));
    wscanf_s(L"%s", inName, (unsigned)_countof(inName));
    si.pUserName = inName;

    wchar_t inMail[MAX_PATH * 2] = { 0 };
    wprintf(TEXT("Email: "));
    wscanf_s(L"%s", inMail, (unsigned)_countof(inMail));
    si.pEMail = inMail;

    char inHWID[MAX_PATH * 2] = { 0 };
    wprintf(TEXT("HWID: "));
    wscanf_s(L"%S", inHWID, (unsigned)_countof(inHWID));
    si.pHardwareID = inHWID;

    DWORD time = 0;
    wprintf(TEXT("Time Limit, 0 to skip: "));
    wscanf_s(L"%d", &time);
    if (time != 0)
    {
        si.nRunningTimeLimit = (BYTE)time;
        si.flags |= HAS_TIME_LIMIT;
    }

    DWORD expDate = 0;
    wprintf(TEXT("Expire Date (YYYYMMDD), 0 to skip: "));
    wscanf_s(L"%d", &expDate);
    if (expDate != 0)
    {
        si.dwExpDate = expDate;
        si.flags |= HAS_EXP_DATE;
    }

    DWORD bldDate = 0;
    wprintf(TEXT("Max Build Date (YYYYMMDD), 0 to skip: "));
    wscanf_s(L"%d", &bldDate);
    if (bldDate != 0)
    {
        si.dwMaxBuildDate = bldDate;
        si.flags |= HAS_MAX_BUILD_DATE;
    }

    si.nRunningTimeLimit = 30;
    si.dwExpDate = 20190101;
    si.dwMaxBuildDate = 20180101;

    char *pBuf = NULL;
    VMProtectErrors res = VMProtectGenerateSerialNumber(&pi, &si, &pBuf);
    if (res == ALL_RIGHT)
    {
        wprintf(L"******************************************\n");
        wprintf(L"***************License Info***************\n");
        wprintf(L"User Name: %s\n", si.pUserName);
        wprintf(L"Email: %s\n", si.pEMail);
        wprintf(L"Hardware ID: %S\n", si.pHardwareID);
        wprintf(L"Expire Date: %04d-%02d-%02d\n", si.dwExpDate / 10000, (si.dwExpDate / 100) % 100, si.dwExpDate % 100);
        wprintf(L"Max Build Date: %04d-%02d-%02d\n", si.dwMaxBuildDate / 10000, (si.dwMaxBuildDate / 100) % 100, si.dwMaxBuildDate % 100);
        wprintf(L"Running Time Limit: %d min(s)\n", si.nRunningTimeLimit);
        wprintf(L"******************************************\n");

        wchar_t pathBuf[MAX_PATH * 2];
        ZeroMemory(pathBuf, MAX_PATH * 2 * sizeof(wchar_t));
        GetCurrentDirectory(MAX_PATH * 2, pathBuf);

        SYSTEMTIME st = { 0 };
        GetLocalTime(&st);

        wchar_t pathName[MAX_PATH];
        ZeroMemory(pathName, MAX_PATH * sizeof(wchar_t));
        swprintf_s(pathName, MAX_PATH, L"%04d%02d%02d%02d%02d%02d_%s_%s_%S",
            st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond, 
            si.pUserName, si.pEMail, si.pHardwareID);

        swprintf_s(pathBuf, MAX_PATH * 2, L"%s\\%s", pathBuf, pathName);

        SECURITY_ATTRIBUTES sa = { 0 };
        sa.nLength = sizeof(sa);
        sa.lpSecurityDescriptor = nullptr;
        sa.bInheritHandle = false;

        if(CreateDirectory(pathBuf, &sa))
        {
            wprintf(L"Out dir:\n%s\n", pathName);

            wchar_t fnBuf[MAX_PATH * 2];
            ZeroMemory(fnBuf, MAX_PATH * 2 * sizeof(wchar_t));
            swprintf_s(fnBuf, MAX_PATH * 2, L"%s\\%s", pathBuf, LICENSE_FILE_NAME);

            FILE *pFile = nullptr;
            if (0 == _wfopen_s(&pFile, fnBuf, L"w"))
            {
                wprintf(L"License file %s generated\n", LICENSE_FILE_NAME);
                assert(strlen(pBuf) == fwrite(pBuf, 1, strlen(pBuf), pFile));
                fclose(pFile);
            }
            else
            {
                wprintf(L"Can't open file %s for write\n", fnBuf);
            }

            ZeroMemory(fnBuf, MAX_PATH * 2 * sizeof(wchar_t));
            swprintf_s(fnBuf, MAX_PATH * 2, L"%s\\%s", pathBuf, INFO_FILE_NAME);

            if (0 == _wfopen_s(&pFile, fnBuf, L"w"))
            {
                wprintf(L"Info file %s generated.\n", INFO_FILE_NAME);
                wchar_t line[MAX_PATH * 2] = { 0 };
                char wl[MAX_PATH * 2] = { 0 };

                size_t strLen = 0;

                swprintf_s(line, MAX_PATH, L"User Name: %s\n", si.pUserName);
                wcstombs_s(&strLen, wl, sizeof(wl), line, wcslen(line) * sizeof(wchar_t));
                assert(strlen(wl) == fwrite(wl, 1, strlen(wl), pFile));

                swprintf_s(line, MAX_PATH, L"Email: %s\n", si.pEMail);
                wcstombs_s(&strLen, wl, sizeof(wl), line, wcslen(line) * sizeof(wchar_t));
                assert(strlen(wl) == fwrite(wl, 1, strlen(wl), pFile));

                swprintf_s(line, MAX_PATH, L"Hardware ID: %S\n", si.pHardwareID);
                wcstombs_s(&strLen, wl, sizeof(wl), line, wcslen(line) * sizeof(wchar_t));
                assert(strlen(wl) == fwrite(wl, 1, strlen(wl), pFile));

                swprintf_s(line, MAX_PATH, L"Expire Date: %04d-%02d-%02d\n", si.dwExpDate/10000, (si.dwExpDate / 100) % 100, si.dwExpDate % 100);
                wcstombs_s(&strLen, wl, sizeof(wl), line, wcslen(line) * sizeof(wchar_t));
                assert(strlen(wl) == fwrite(wl, 1, strlen(wl), pFile));

                swprintf_s(line, MAX_PATH, L"Max Build Date: %04d-%02d-%02d\n", si.dwMaxBuildDate / 10000, (si.dwMaxBuildDate / 100) % 100, si.dwMaxBuildDate % 100);
                wcstombs_s(&strLen, wl, sizeof(wl), line, wcslen(line) * sizeof(wchar_t));
                assert(strlen(wl) == fwrite(wl, 1, strlen(wl), pFile));

                swprintf_s(line, MAX_PATH, L"Running Time Limit: %d min(s)\n", si.nRunningTimeLimit);
                wcstombs_s(&strLen, wl, sizeof(wl), line, wcslen(line) * sizeof(wchar_t));
                assert(strlen(wl) == fwrite(wl, 1, strlen(wl), pFile));

                fclose(pFile);
            }
            else
            {
                wprintf(L"Can't open file %s for write\n", fnBuf);
            }
        }
        else
        {
            wprintf(L"Can't create directory %s for output\n", pathName);
        }
        VMProtectFreeSerialNumberMemory(pBuf);
    }
    else
    {
        printf("Error: %d\n", res);
    }

    return 0;
}

