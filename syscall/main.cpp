#include <iostream>
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>

#include "syscall.h"

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
    char func_name[] = { "ZwOpenProcess" };

    HMODULE hModle = GetModuleHandleA("ntdll.dll");
    PVOID func_address = GetProcAddress(hModle, func_name);
    printf("GetProcAddress: %p : 0x%p\r\n", hModle, func_address);

	// calc hash
    DWORD hash_name = SW2_HashSyscall(func_name); // 0x6419a5ac
	printf("%s : 0x%x\r\n", func_name, hash_name);

	// get_library_address(NTDLL_DLL, FALSE)
	DWORD ret = SW2_GetSyscallNumber(hash_name);	
	printf("SW2_GetSyscallNumber: 0x%x \r\n", ret);	//   wprintf(L"%ls\n", L"ntdll.dll");

	HANDLE hProcess = NULL;
	DWORD dwPid = 1036; // demo
    CLIENT_ID uPid = { (HANDLE)(DWORD_PTR)dwPid, 0 };

	OBJECT_ATTRIBUTES ObjectAttributes;
	InitializeObjectAttributes(&ObjectAttributes, NULL, 0, NULL, NULL);
	
    // syscall api: NtOpenProcess
    NTSTATUS status = NtOpenProcess(&hProcess, PROCESS_QUERY_INFORMATION| PROCESS_VM_READ, &ObjectAttributes, &uPid);
	printf("NtOpenProcess: 0x%p\r\n", hProcess);

    getProcInfo(hProcess);
        
    // syscalll api: NtClose
    NtClose(hProcess);

    return 0;
}

EXTERN_C int check_syscallnumber();

int main() {

    std::cout << "Hello World!\n";

    //check_syscallnumber();

    test_syscall();

    return 0;
}