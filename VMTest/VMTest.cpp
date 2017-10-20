// VMTest.cpp : Defines the entry point for the console application.
//

#include "stdafx.h"
#include "Windows.h"
#include "VMProtectSDK.h"
#include "Shlwapi.h"

#define PRINT_HELPER(state, flag) if (state & flag) printf("%s ", #flag)
void print_state(int state)
{
    if (state == 0)
    {
        printf("state = 0\n");
        printf("Registered!\n");
        return;
    }

    printf("state = ");
    PRINT_HELPER(state, SERIAL_STATE_FLAG_CORRUPTED);
    PRINT_HELPER(state, SERIAL_STATE_FLAG_INVALID);
    PRINT_HELPER(state, SERIAL_STATE_FLAG_BLACKLISTED);
    PRINT_HELPER(state, SERIAL_STATE_FLAG_DATE_EXPIRED);
    PRINT_HELPER(state, SERIAL_STATE_FLAG_RUNNING_TIME_OVER);
    PRINT_HELPER(state, SERIAL_STATE_FLAG_BAD_HWID);
    PRINT_HELPER(state, SERIAL_STATE_FLAG_MAX_BUILD_EXPIRED);
    printf("\n");
    printf("Please register!\n");
}

int main()
{
    char sn[MAX_PATH * 4] = { 0 };

    wchar_t fnBuf[MAX_PATH * 2] = {0};
    GetModuleFileName(NULL, fnBuf, MAX_PATH * 2);
    PathRemoveFileSpec(fnBuf);

    wchar_t *pLicFileName = L"license.lic";
    swprintf_s(fnBuf, MAX_PATH * 2, L"%s\\%s", fnBuf, pLicFileName);

    FILE *pLicFile = nullptr;
    if (0 == _wfopen_s(&pLicFile, fnBuf, L"r"))
    {
        char buf[MAX_PATH] = {0};
        while (fgets(buf, MAX_PATH, pLicFile))
        {
            if (buf[strlen(buf) - 1] == 0xA)
            {
                buf[strlen(buf) - 1] = 0;
            }
            strcat_s(sn, MAX_PATH * 4, buf);
        }
        fclose(pLicFile);
    }

    int nSize = VMProtectGetCurrentHWID(NULL, 0);
    char *buf = new char[nSize];
    VMProtectGetCurrentHWID(buf, nSize);
    printf("HWID: %s\n", buf);
    delete[] buf;

    int res = VMProtectSetSerialNumber(sn);
    print_state(res);

    VMProtectSerialNumberData sd = { 0 };
    VMProtectGetSerialNumberData(&sd, sizeof(sd));
    printf("State: %d\n", sd.nState);
    printf("User name: %ls\n", sd.wUserName);
    printf("Email: %ls\n", sd.wEMail);
    printf("Expire date: %d-%d-%d\n", sd.dtExpire.wYear, sd.dtExpire.bMonth, sd.dtExpire.bDay);
    printf("Max build date: %d-%d-%d\n", sd.dtMaxBuild.wYear, sd.dtMaxBuild.bMonth, sd.dtMaxBuild.bDay);
    printf("Running minutes: %d\n", sd.bRunningTime);

    SYSTEMTIME st = { 0 };
    while (1)
    {
        GetLocalTime(&st);
        printf("%d/%d/%d - %02d:%02d:%02d\n", st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
        Sleep(10000);
        res = VMProtectGetSerialNumberState();
        print_state(res);
    }

    return 0;
}

