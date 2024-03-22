#include "syscall.h"

DWORD SW2_HashSyscall(PCSTR FunctionName)
{
    DWORD i = 0;
    DWORD Hash = SW2_SEED;

    while (FunctionName[i])
    {
        WORD PartialName = *(WORD*)((DWORD_PTR)FunctionName + i++);
        Hash ^= PartialName + SW2_ROR8(Hash);
    }

    return Hash;
}

SW2_SYSCALL_LIST g_SyscallList = { 0 };

BOOL SW2_PopulateSyscallList() {
    
    if (g_SyscallList.Count) return TRUE;

#if defined(_WIN64)
    PSW2_PEB Peb = (PSW2_PEB)__readgsqword(0x60);
#else
    PSW2_PEB Peb = (PSW2_PEB)__readfsdword(0x30);
#endif // (_WIN64)

    PSW2_PEB_LDR_DATA Ldr = Peb->Ldr;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    PVOID DllBase = NULL;

    // 1. Get the DllBase address of NTDLL.dll  NTDLL is not guaranteed to be the second in the list
    PSW2_LDR_DATA_TABLE_ENTRY LdrEntry = LdrEntry = Ldr->Reserved2[1];
    for (; LdrEntry->DllBase != NULL; LdrEntry = (PSW2_LDR_DATA_TABLE_ENTRY)LdrEntry->Reserved1[0])
    {
        DllBase = LdrEntry->DllBase;
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)DllBase;
        PIMAGE_NT_HEADERS NtHeaders = SW2_RVA2VA(PIMAGE_NT_HEADERS, DllBase, dosHeader->e_lfanew);
        PIMAGE_DATA_DIRECTORY DataDirectory = (PIMAGE_DATA_DIRECTORY)NtHeaders->OptionalHeader.DataDirectory;
        DWORD VirtualAddress = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (VirtualAddress == 0)    continue;

        // get export table
        ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)SW2_RVA2VA(ULONG_PTR, DllBase, VirtualAddress);

        // get ntdll name from modules.ExportDirectory->Name 
        PCHAR DllName = SW2_RVA2VA(PCHAR, DllBase, ExportDirectory->Name);

        // Check, If this is NTDLL.dll, exit loop
        if ((*(ULONG*)DllName | 0x20202020) != 'ldtn') continue;
        if ((*(ULONG*)(DllName + 4) | 0x20202020) == 'ld.l') break;
    }

    if (!ExportDirectory) return FALSE;

    // 2. get Name of ExportFunction from ntdll.dll
    DWORD NumberOfNames = ExportDirectory->NumberOfFunctions;
    PDWORD Functions = SW2_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfFunctions);
    PDWORD Names = SW2_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfNames);
    PWORD Ordinals = SW2_RVA2VA(PWORD, DllBase, ExportDirectory->AddressOfNameOrdinals);

    // 2.1 Populate SW2_SyscallList with unsorted Zw* entries; 
    DWORD i = 0;
    PSW2_SYSCALL_ENTRY Entries = g_SyscallList.Entries;
    do
    {
        PCHAR FunctionName = SW2_RVA2VA(PCHAR, DllBase, Names[NumberOfNames - 1]);

        // Is this a system call?
        if (*(USHORT*)FunctionName == 'wZ')
        {
            Entries[i].Hash = SW2_HashSyscall(FunctionName);
            Entries[i].Address = Functions[Ordinals[NumberOfNames - 1]];    // 导出函数 RVA

            i++;
            if (i == SW2_MAX_ENTRIES) break;
        }
    } while (--NumberOfNames);

    // Save total number of system call found.
    g_SyscallList.Count = i;

    // 3. Sort the list by address in ascending order.
    for (DWORD i = 0; i < g_SyscallList.Count-1; i++)
    {
        for (DWORD j = 0; j < g_SyscallList.Count - i - 1; j++)
        {
            if (Entries[j].Address > Entries[j + 1].Address)
            {
                // Swap entries
                SW2_SYSCALL_ENTRY TempEntry = { 0 };
                TempEntry.Hash = Entries[j].Hash;
                TempEntry.Address = Entries[j].Address;

                Entries[j].Hash = Entries[j + 1].Hash;
                Entries[j].Address = Entries[j + 1].Address;

                Entries[j + 1].Hash = TempEntry.Hash;
                Entries[j + 1].Address = TempEntry.Address;
            }
        }
    }

    return TRUE;
}

// 只能查找 Zw 系列函数
DWORD SW2_GetSyscallNumber(DWORD FunctionHash) {

    // Ensure SW2_SyscallList is populated.
    if (!SW2_PopulateSyscallList()) return -1;

    for (DWORD i = 0; i < g_SyscallList.Count; i++)
    {
        if (FunctionHash == g_SyscallList.Entries[i].Hash)
        {
            return i;
        }
    }

    return -1;
}

/*                            测试                            */
typedef struct _SW2_SYSCALL_ENTRY_TEST
{
    PCHAR Hash;
    DWORD Address;
} SW2_SYSCALL_ENTRY_TEST, * PSW2_SYSCALL_ENTRY_TEST;

typedef struct _SW2_SYSCALL_LIST_TEST
{
    DWORD Count;
    SW2_SYSCALL_ENTRY_TEST Entries[SW2_MAX_ENTRIES];
} SW2_SYSCALL_LIST_TEST, * PSW2_SYSCALL_LIST_TEST;

SW2_SYSCALL_LIST_TEST g_SyscallListTest = { 0 };


BOOL SW2_PopulateSyscallList_Test() {

#if defined(_WIN64)
    PSW2_PEB Peb = (PSW2_PEB)__readgsqword(0x60);
#else
    PSW2_PEB Peb = (PSW2_PEB)__readfsdword(0x30);
#endif // (_WIN64)

    PSW2_PEB_LDR_DATA Ldr = Peb->Ldr;
    PIMAGE_EXPORT_DIRECTORY ExportDirectory = NULL;
    PVOID DllBase = NULL;

    // 1. Get the DllBase address of NTDLL.dll  NTDLL is not guaranteed to be the second in the list
    PSW2_LDR_DATA_TABLE_ENTRY LdrEntry = LdrEntry = Ldr->Reserved2[1];
    for (; LdrEntry->DllBase != NULL; LdrEntry = (PSW2_LDR_DATA_TABLE_ENTRY)LdrEntry->Reserved1[0])
    {
        DllBase = LdrEntry->DllBase;
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)DllBase;
        PIMAGE_NT_HEADERS NtHeaders = SW2_RVA2VA(PIMAGE_NT_HEADERS, DllBase, dosHeader->e_lfanew);
        PIMAGE_DATA_DIRECTORY DataDirectory = (PIMAGE_DATA_DIRECTORY)NtHeaders->OptionalHeader.DataDirectory;
        DWORD VirtualAddress = DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress;
        if (VirtualAddress == 0)    continue;

        // get export table
        ExportDirectory = (PIMAGE_EXPORT_DIRECTORY)SW2_RVA2VA(ULONG_PTR, DllBase, VirtualAddress);

        // get ntdll name from modules.ExportDirectory->Name 
        PCHAR DllName = SW2_RVA2VA(PCHAR, DllBase, ExportDirectory->Name);

        // Check, If this is NTDLL.dll, exit loop
        if ((*(ULONG*)DllName | 0x20202020) != 'ldtn') continue;
        if ((*(ULONG*)(DllName + 4) | 0x20202020) == 'ld.l') break;
    }

    if (!ExportDirectory) return FALSE;

    // 2. get Name of ExportFunction from ntdll.dll
    DWORD NumberOfNames = ExportDirectory->NumberOfFunctions;
    PDWORD Functions = SW2_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfFunctions);
    PDWORD Names = SW2_RVA2VA(PDWORD, DllBase, ExportDirectory->AddressOfNames);
    PWORD Ordinals = SW2_RVA2VA(PWORD, DllBase, ExportDirectory->AddressOfNameOrdinals);

    // 2.1 Populate SW2_SyscallList with unsorted Zw* entries; 
    DWORD i = 0;
    PSW2_SYSCALL_ENTRY_TEST Entries = g_SyscallListTest.Entries;
    do
    {
        PCHAR FunctionName = SW2_RVA2VA(PCHAR, DllBase, Names[NumberOfNames - 1]);

        // Is this a system call?
        if (*(USHORT*)FunctionName == 'wZ')
        {
            //Entries[i].Hash = SW2_HashSyscall(FunctionName);
            Entries[i].Hash = (PCHAR)FunctionName;
            Entries[i].Address = Functions[Ordinals[NumberOfNames - 1]];    // 导出函数 RVA

            i++;
            if (i == SW2_MAX_ENTRIES) break;
        }
    } while (--NumberOfNames);

    // Save total number of system call found.
    g_SyscallListTest.Count = i;

    // 3. Sort the list by address in ascending order.
    for (DWORD i = 0; i < g_SyscallListTest.Count - 1; i++)
    {
        for (DWORD j = 0; j < g_SyscallListTest.Count - i - 1; j++)
        {
            // 按照地址排序
            if (Entries[j].Address > Entries[j + 1].Address)
            {
                // Swap entries
                SW2_SYSCALL_ENTRY_TEST TempEntry = { 0 };
                TempEntry.Hash = Entries[j].Hash;
                TempEntry.Address = Entries[j].Address;

                Entries[j].Hash = Entries[j + 1].Hash;
                Entries[j].Address = Entries[j + 1].Address;

                Entries[j + 1].Hash = TempEntry.Hash;
                Entries[j + 1].Address = TempEntry.Address;
            }
        }
    }

    return TRUE;
}

int check_syscallnumber() {

    DWORD ret = SW2_PopulateSyscallList_Test();
    printf("SW2_PopulateSyscallList_Test: 0x%x \r\n", ret);	//   wprintf(L"%ls\n", L"ntdll.dll");

    HMODULE hModule = GetModuleHandleA("ntdll.dll");
    if (hModule == NULL) {
        return 1;
    }

    PBYTE base = (PBYTE)hModule;

    PSW2_SYSCALL_ENTRY_TEST Entries = g_SyscallListTest.Entries;
    for (DWORD i = 0; i < g_SyscallListTest.Count; i++)
    {
        PCHAR func_name = (PCHAR)Entries[i].Hash;
        PVOID func_address = (PVOID)(Entries[i].Address + base);
        PVOID func_address2 = GetProcAddress(hModule, func_name);

        // get syscall number
        PBYTE pp = (PBYTE)func_address;
        pp += 4;
        DWORD callnumber = *(PDWORD)pp;

        //printf("Call Number: 0x%x -- 0x%x \r\n", i, callnumber);
        printf("Call Number: 0x%x -- 0x%x, Address: 0x%p -- 0x%p , FuncName: %s \r\n", i, callnumber, func_address, func_address2, func_name);
    }

    return 0;
}