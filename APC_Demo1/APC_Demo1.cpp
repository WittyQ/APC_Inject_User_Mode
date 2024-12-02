// APC_Demo1.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <iostream>
#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include<Psapi.h>

DWORD GetProcessIdFromFullPath(const std::wstring& processPath) {
    if (0) {
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot == INVALID_HANDLE_VALUE) {
            MessageBox(NULL, L"CreateToolhelp32Snapshot failed.", L"Error", MB_OK);
            return 0;
        }
        PROCESSENTRY32W  pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);
        if (!Process32FirstW(hSnapshot, &pe32)) {
            MessageBox(NULL, L"Process32First failed.", L"Error", MB_OK);
            CloseHandle(hSnapshot);
            return 0;
        }
        do {
            // get process full path
            WCHAR szExeFile[MAX_PATH] = { 0 };
            HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pe32.th32ProcessID);
            if (hProcess == NULL) {
                continue;
            }

            if (GetProcessImageFileName(hProcess, szExeFile, MAX_PATH) > 0) {
                if (processPath == szExeFile) {
                    CloseHandle(hProcess);
                    CloseHandle(hSnapshot);
                    return pe32.th32ProcessID;
                }
            }
            CloseHandle(hProcess);
        } while (Process32Next(hSnapshot, &pe32));

        CloseHandle(hSnapshot);
        return 0; // if can't find process reutrn 0
    }
    DWORD aProcesses[1024], cbNeeded, cProcesses;
    if (!EnumProcesses(aProcesses, sizeof(aProcesses), &cbNeeded)) {
        return 0;
    }

    cProcesses = cbNeeded / sizeof(DWORD);

    // enum process id
    for (unsigned int i = 0; i < cProcesses; i++) {
        if (aProcesses[i] == 0) {
            continue;
        }

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, aProcesses[i]);
        if (hProcess) {
            WCHAR szProcessName[MAX_PATH] = L"<unknown>";
            // get exe name
            if (GetModuleFileNameEx(hProcess, NULL, szProcessName, sizeof(szProcessName) / sizeof(WCHAR))) {
                // compare pth
                if (processPath == szProcessName) {
                    CloseHandle(hProcess);
                    return aProcesses[i];
                }
            }
            CloseHandle(hProcess);
        }
    }

    return 0;
}

bool ListProcessThreads(DWORD processID, std::vector<DWORD>& vctThread) {
    HANDLE hThreadSnap = INVALID_HANDLE_VALUE;
    THREADENTRY32 te32;
    vctThread.clear();

    // Take a snapshot of all running threads  
    hThreadSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hThreadSnap == INVALID_HANDLE_VALUE) {
        MessageBox(NULL, L"CreateToolhelp32Snapshot (of threads) failed", L"Error", MB_OK);
        return vctThread.size() != 0;
    }

    // Fill in the size of the structure before using it. 
    te32.dwSize = sizeof(THREADENTRY32);

    // Retrieve information about the first thread,
    // and exit if unsuccessful
    if (!Thread32First(hThreadSnap, &te32)) {
        MessageBox(NULL, L"Thread32First failed", L"Error", MB_OK);
        CloseHandle(hThreadSnap);     // Must clean up the snapshot object!
        return vctThread.size() != 0;
    }

    // Now walk the thread list of the system,
    // and display information about each thread
    // associated with the specified process
    do {
        if (te32.th32OwnerProcessID == processID) {
            vctThread.emplace_back(te32.th32ThreadID);
        }
    } while (Thread32Next(hThreadSnap, &te32));

    // Do not forget to clean up the snapshot object.
    CloseHandle(hThreadSnap);
    return vctThread.size() != 0;
}

int main()
{
    const std::wstring path = L"C:\\Users\\13984\\Desktop\\TargetProcess.exe";
    DWORD pid = GetProcessIdFromFullPath(path);
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, pid);
    if (!hProcess) {
        std::cerr << "OpenProcess failed" << std::endl;
        return -1;
    }

    std::vector<DWORD> vctThreads;
    if (!ListProcessThreads(pid, vctThreads)) {
        MessageBox(NULL, L"enum target process thread failed\n", L"Error", MB_OK);
        CloseHandle(hProcess);
        return 1;
    }

    //LoadLibraryA
    HMODULE hModule = GetModuleHandleA("Kernel32.dll");
    if(!hModule) {
        std::cerr << "GetModuleHandleA failed" << std::endl;
        return -1;
    }
    PVOID func = GetProcAddress(hModule, "LoadLibraryA");

    PUCHAR Memory = (PUCHAR)VirtualAllocEx(hProcess, NULL, 0x1000, MEM_COMMIT, PAGE_READWRITE);
    if (!Memory) {
        std::cerr << "VirtualAllocEx failed" << std::endl;
        return -1;
    }

    const char * buf = "C:\\Users\\13984\\Desktop\\TestDll.dll";
    SIZE_T proc = NULL;
    if (!WriteProcessMemory(hProcess, Memory, buf, strlen(buf) + 1, &proc)) {
        std::cerr << "WriteProcessMemory failed" << std::endl;
        return -1;
    }

    for (auto thread : vctThreads) {
        HANDLE hThread = OpenThread(PROCESS_ALL_ACCESS, FALSE, thread);
        if (hThread) {
            QueueUserAPC((PAPCFUNC)func, hThread, (ULONG_PTR)Memory);
            CloseHandle(hThread);
        }
    }
    system("pause");
    return 0;
}

