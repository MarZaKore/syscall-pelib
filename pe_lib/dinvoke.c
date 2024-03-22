#include "dinvoke.h"

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

// 通过判断 模块 PE属性 判断 是否是 dll
BOOL is_dll(HMODULE hLibrary)
{
	PIMAGE_DOS_HEADER dos;
	PIMAGE_NT_HEADERS nt;

	if (!hLibrary)
		return FALSE;

	dos = (PIMAGE_DOS_HEADER)hLibrary;
	if (dos->e_magic != MZ)
		return FALSE;

	nt = RVA(PIMAGE_NT_HEADERS, hLibrary, dos->e_lfanew);
	if (nt->Signature != IMAGE_NT_SIGNATURE)
		return FALSE;

	USHORT Characteristics = nt->FileHeader.Characteristics;
	if ((Characteristics & IMAGE_FILE_DLL) != IMAGE_FILE_DLL)
		return FALSE;

	return TRUE;
}

// 查找旧版导出 ，相当于查找函数地址的最后手段（查找所有模块）
PVOID find_legacy_export(HMODULE hOriginalLibrary, DWORD fhash)
{
	PVOID addr;
	PND_PEB Peb = (PND_PEB)READ_MEMLOC(PEB_OFFSET);
	PND_PEB_LDR_DATA Ldr = Peb->Ldr;
	PVOID FirstEntry = &Ldr->InMemoryOrderModuleList.Flink;
	PND_LDR_DATA_TABLE_ENTRY Entry = (PND_LDR_DATA_TABLE_ENTRY)Ldr->InMemoryOrderModuleList.Flink;

	for (; Entry != FirstEntry; Entry = (PND_LDR_DATA_TABLE_ENTRY)Entry->InMemoryOrderLinks.Flink)
	{
		if (Entry->DllBase == hOriginalLibrary)
			continue;

		addr = get_function_address(Entry->DllBase, fhash, 0);
		if (!addr)
			continue;

		return addr;
	}

	return NULL;
}

// 修复导出表中的转发函数
PVOID resolve_reference(HMODULE hOriginalLibrary, PVOID addr)
{
	HANDLE hLibrary;
	PVOID new_addr;
	LPCSTR api;

	api = &strrchr(addr, '.')[1];
	size_t dll_length = (ULONG_PTR)api - (ULONG_PTR)addr;
	char dll[MAX_PATH] = { 0 };
	//strncpy(dll, (LPCSTR)addr, dll_length);
	strncpy_s(dll, MAX_PATH, (LPCSTR)addr, dll_length);
	//strcat(dll, "dll");
	strcat_s(dll, MAX_PATH, "dll");

	wchar_t wc_dll[MAX_PATH] = { 0 };
	//mbstowcs(wc_dll, dll, MAX_PATH);
	int wideCharLength = MultiByteToWideChar(CP_UTF8, 0, dll, -1, NULL, 0);
	//wchar_t* wideCharString = (wchar_t*)malloc(wideCharLength * sizeof(wchar_t));
	wchar_t* wideCharString = wc_dll;
	// 使用 MultiByteToWideChar 函数将单字节字符串转换为宽字节字符串
	MultiByteToWideChar(CP_UTF8, 0, dll, -1, wideCharString, wideCharLength);

	hLibrary = get_library_address(wc_dll, FALSE);
	if (!hLibrary)
	{
		new_addr = find_legacy_export(hOriginalLibrary, SW2_HashSyscall(api));
		return new_addr;
	}

	new_addr = get_function_address(hLibrary, SW2_HashSyscall(api), 0);

	return new_addr;
}

// 自定义 getProcAddress: 遍历导出表，比较函数名称hash 查找函数地址； 导出需要查找函数
PVOID get_function_address(HMODULE hLibrary, DWORD fhash, WORD ordinal)
{
	PIMAGE_DOS_HEADER       dos;
	PIMAGE_NT_HEADERS       nt;
	PIMAGE_DATA_DIRECTORY   data;
	PIMAGE_EXPORT_DIRECTORY exp;
	DWORD                   exp_size;
	PDWORD                  adr;
	PDWORD                  sym;
	PWORD                   ord;
	LPCSTR                  api;
	PVOID                   addr;

	if (!is_dll(hLibrary))
		return NULL;

	dos = (PIMAGE_DOS_HEADER)hLibrary;
	nt = RVA(PIMAGE_NT_HEADERS, hLibrary, dos->e_lfanew);
	data = (PIMAGE_DATA_DIRECTORY)nt->OptionalHeader.DataDirectory;

	if (!data->Size || !data->VirtualAddress)
		return NULL;

	exp = RVA(PIMAGE_EXPORT_DIRECTORY, hLibrary, data->VirtualAddress);
	exp_size = data[IMAGE_DIRECTORY_ENTRY_EXPORT].Size;

	adr = RVA(PDWORD, hLibrary, exp->AddressOfFunctions);
	sym = RVA(PDWORD, hLibrary, exp->AddressOfNames);
	ord = RVA(PWORD, hLibrary, exp->AddressOfNameOrdinals);

	addr = NULL;
	if (fhash)
	{
		for (DWORD i = 0; i < exp->NumberOfNames; i++)
		{
			api = RVA(LPCSTR, hLibrary, sym[i]);
			if (fhash == SW2_HashSyscall(api))
			{
				addr = RVA(PVOID, hLibrary, adr[ord[i]]);
				break;
			}
		}
	}
	else
	{
		addr = RVA(PVOID, hLibrary, adr[ordinal - exp->Base]);
	}
	if (!addr)
		return NULL;

	// 修复转发函数
	if (addr >= (PVOID)exp && addr < (PVOID)((PCHAR)exp + exp_size))
		addr = resolve_reference(hLibrary, addr);

	return addr;
}

// 自定义 loadLibrary： 对于已加载模块遍历 Peb->Ldr; 对于未加载的模块，DoLoad判断是否加载 获取LdrLoadDll 函数进行动态加载
typedef NTSTATUS(WINAPI* LdrLoadDll_t)(PWCHAR, ULONG, PUNICODE_STRING, PHANDLE);
HANDLE get_library_address(LPWSTR LibName, BOOL DoLoad)
{
	PND_PEB Peb = (PND_PEB)READ_MEMLOC(PEB_OFFSET);
	PND_PEB_LDR_DATA Ldr = Peb->Ldr;
	PVOID FirstEntry = &Ldr->InMemoryOrderModuleList.Flink;
	PND_LDR_DATA_TABLE_ENTRY Entry = (PND_LDR_DATA_TABLE_ENTRY)Ldr->InMemoryOrderModuleList.Flink;

	do
	{
		if (!_wcsicmp(LibName, Entry->BaseDllName.Buffer))
			return Entry->DllBase;

		Entry = (PND_LDR_DATA_TABLE_ENTRY)Entry->InMemoryOrderLinks.Flink;
	} while (Entry != FirstEntry);

	if (!DoLoad)
		return NULL;

	LdrLoadDll_t LdrLoadDll = (LdrLoadDll_t)get_function_address(get_library_address(NTDLL_DLL, FALSE), LdrLoadDll_SW2_HASH, 0);
	if (!LdrLoadDll)
		return NULL;

	UNICODE_STRING ModuleFileName;
	ModuleFileName.Buffer = LibName;
	ModuleFileName.Length = wcsnlen(ModuleFileName.Buffer, MAX_PATH);
	ModuleFileName.Length *= 2;
	ModuleFileName.MaximumLength = ModuleFileName.Length + 2;

	HANDLE hLibrary = NULL;
	NTSTATUS status = LdrLoadDll(NULL, 0, &ModuleFileName, &hLibrary);
	if (!NT_SUCCESS(status))
		return NULL;

	return hLibrary;
}

// 自定义的加载 dll 实现
HANDLE load_library_pe(LPWSTR LibName) {
	HANDLE hLibrary = NULL;

	// 1. 读取文件

	// 2. 区段拉伸
	
	// 3. 修复重定位
	
	// 4. 修复导入表

	// 5. 修复 cookie 验证

	// 6. 进行 静态变量，静态函数的初始化

	// 7. 抹除 PE 特征


	return hLibrary;
}

void test() {

	char func_name[] = { "LdrLoadDll" };
	DWORD hash_name = SW2_HashSyscall(func_name); // 0x6419a5ac

	printf("%s : 0x%x\r\n", func_name, hash_name);

	// get_library_address(NTDLL_DLL, FALSE)
	HANDLE handle = get_library_address(L"ntdll.dll", FALSE);
	printf("%ws : 0x%p \r\n", NTDLL_DLL, handle);	//   wprintf(L"%ls\n", L"ntdll.dll");

	//#define LdrLoadDll_SW2_HASH 0x6419a5ac
	PVOID func_address = get_function_address(handle, LdrLoadDll_SW2_HASH, 0);

	printf("%s : 0x%p\r\n", func_name, func_address);

	return;
}
