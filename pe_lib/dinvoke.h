#include <Windows.h>
#include <stdio.h>

#ifdef _WIN64
#define PEB_OFFSET 0x60
#define READ_MEMLOC __readgsqword
#else
#define PEB_OFFSET 0x30
#define READ_MEMLOC __readfsdword
#endif

#define RVA(type, base_addr, rva) (type)((ULONG_PTR) base_addr + rva)
#define NT_SUCCESS(Status) ((NTSTATUS)(Status) >= 0)

#define NTDLL_DLL L"ntdll.dll"
#define LdrLoadDll_SW2_HASH 0x6419a5ac

#define MZ 0x5A4D

typedef HMODULE(WINAPI* LOADLIBRARYA)(LPCSTR);

typedef struct _UNICODE_STRING
{
    USHORT Length;
    USHORT MaximumLength;
    PWSTR  Buffer;
} UNICODE_STRING, * PUNICODE_STRING;

typedef struct _ND_LDR_DATA_TABLE_ENTRY
{
    //struct _LIST_ENTRY InLoadOrderLinks;
    struct _LIST_ENTRY InMemoryOrderLinks;
    struct _LIST_ENTRY InInitializationOrderLinks;
    PVOID DllBase;
    PVOID EntryPoint;
    ULONG SizeOfImage;
    UNICODE_STRING FullDllName;
    UNICODE_STRING BaseDllName;
} ND_LDR_DATA_TABLE_ENTRY, *PND_LDR_DATA_TABLE_ENTRY;

typedef struct _ND_PEB_LDR_DATA
{
    ULONG Length;
    UCHAR Initialized;
    PVOID SsHandle;
    struct _LIST_ENTRY InLoadOrderModuleList;
    struct _LIST_ENTRY InMemoryOrderModuleList;
    struct _LIST_ENTRY InInitializationOrderModuleList;
} ND_PEB_LDR_DATA, *PND_PEB_LDR_DATA;

typedef struct _ND_PEB
{
    BYTE Reserved1[2];
    BYTE BeingDebugged;
    BYTE Reserved2[1];
    PVOID Reserved3[2];
    PND_PEB_LDR_DATA Ldr;
} ND_PEB, *PND_PEB;

// 实际使用只需要调用 get_library_address 和 get_function_address 进行模块加载和函数函数地址查找
HANDLE get_function_address(HMODULE hLibrary, DWORD FunctionHash, WORD Ordinal);
HANDLE get_library_address(LPWSTR LibName, BOOL DoLoad);

#define SW2_SEED 0x4BE2A6AA
#define SW2_ROL8(v) (v << 8 | v >> 24)
#define SW2_ROR8(v) (v >> 8 | v << 24)
#define SW2_ROX8(v) ((SW2_SEED % 2) ? SW2_ROL8(v) : SW2_ROR8(v))
DWORD SW2_HashSyscall(PCSTR FunctionName);