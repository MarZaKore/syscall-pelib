#include <iostream>
#include <windows.h>
#include "syscalls.h"
#include <psapi.h>

// 获取目标进程的模块信息
void getProcInfo(HANDLE hProcess) {

    if (hProcess)
    {
        HMODULE hModules[1024];
        DWORD cbNeeded;

        if (EnumProcessModules(hProcess, hModules, sizeof(hModules), &cbNeeded))
        {
            DWORD moduleCount = cbNeeded / sizeof(HMODULE);

            for (DWORD i = 0; i < moduleCount; i++)
            {
                TCHAR szModuleName[MAX_PATH];
                if (GetModuleFileNameEx(hProcess, hModules[i], szModuleName, sizeof(szModuleName) / sizeof(TCHAR)))
                {
                    // 输出模块名称
                    printf("Module name: %p --> %ls\n", hModules[i], szModuleName);
                }
            }
        }
        else
        {
            printf("EnumProcessModules failed with error code: %lu\n", GetLastError());
        }

        //CloseHandle(hProcess);
    }
    else
    {
        printf("OpenProcess failed with error code: %lu\n", GetLastError());
    }
}

// syscall 调用示例
int test_syscall()
{
    HANDLE hProcess = NULL;
    DWORD dwPid = 1036; // demo
    CLIENT_ID uPid = { (HANDLE)(DWORD_PTR)dwPid, 0 };

    OBJECT_ATTRIBUTES ObjectAttributes;
    InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);

    // syscall api: NtOpenProcess
    NTSTATUS status = NtOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, &ObjectAttributes, &uPid);
    printf("NtOpenProcess: 0x%p\r\n", hProcess);

    getProcInfo(hProcess);

    // syscalll api: NtClose
    NtClose(hProcess);

    return 0;
}

int main()
{
    std::cout << "Hello World!\n";
    test_syscall();

    return 0;
}

