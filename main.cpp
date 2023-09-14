#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <string>
#include <vector>
#include <exception>

#include <winternl.h>
#include <psapi.h>

#include <codecvt>

#include <cwctype>

#include <iostream>
#include <algorithm>

#ifdef _WIN64
typedef unsigned __int64 PTR;
typedef unsigned __int64 RAV;
#else
typedef unsigned int PTR;
typedef unsigned int RAV;
#endif

typedef NTSTATUS(WINAPI *PNtQueryInformationProcess)(
	_In_      HANDLE           ProcessHandle,
	_In_      PROCESSINFOCLASS ProcessInformationClass,
	_Out_     PVOID            ProcessInformation,
	_In_      ULONG            ProcessInformationLength,
	_Out_opt_ PULONG           ReturnLength
	);

class Dependency {
public:
public:
	std::string m_Name;
	std::vector<std::string> m_vFunctions;
};

class InjectableDll {
public:
	InjectableDll() {}
	bool Load(std::wstring);
public:
	std::vector<unsigned char> m_vData;
	std::vector<Dependency> m_vDependencies;
};


bool InjectableDll::Load(std::wstring path) {

	HANDLE hFile = CreateFileW(path.c_str(), GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, 0);
	if (hFile == INVALID_HANDLE_VALUE) {
		printf("Couldn't find file \"%S\"!\n", path.c_str());
		return false;
	}

	DWORD dwFileSizeHigh;
	DWORD dwFileSizeLow = GetFileSize(hFile, &dwFileSizeHigh);
	if (dwFileSizeLow == INVALID_FILE_SIZE) {
		CloseHandle(hFile);
		printf("Couldn't read file size!\n");
		return false;
	}

#ifndef _WIN64
	if (dwFileSizeHigh) {
		CloseHandle(hFile);
		printf("Can't read files bigger than 4GB with a 32 bit process!\n");
		return false;
	}
#endif

	size_t fileSize =
#ifdef _WIN64
	((size_t)dwFileSizeHigh << 32) |
#endif
		dwFileSizeLow;

	m_vData.resize(fileSize);

	size_t readTotal = 0;
	while (readTotal < fileSize) {
		size_t left = fileSize - readTotal;
		size_t toRead = (left > 0xFFFFFFFF) ? 0xFFFFFFFF : left;
		DWORD dwRead;
		if (!ReadFile(hFile, &m_vData[readTotal], (DWORD)toRead, &dwRead, 0) || dwRead != (DWORD)toRead) {
			CloseHandle(hFile);
			printf("File read failed!\n");
			return false;
		}
		readTotal += dwRead;
	}

	CloseHandle(hFile);

	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER)&m_vData[0];
	if (pDosHeader->e_magic != 0x5A4D) {
		printf("IMAGE_DOS_HEADER magic number wrong!\n");
		return false;
	}

	if (pDosHeader->e_lfanew == 0) {
		printf("Dll file doesn't contain NT headers!\n");
		return false;
	}

	DWORD* pSignature = (PDWORD)&m_vData[pDosHeader->e_lfanew];
	if (*pSignature != 0x00004550) {
		printf("Dll file signature isn't correct!\n");
		return false;
	}

	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER)(pSignature + 1);
#ifdef _WIN64
	if (pFileHeader->Machine != 0x8664) {
		printf("Dll file isn't 64 bit!\n");
		return false;
	}
#else
	if (pFileHeader->Machine != 0x014C) {
		printf("Dll file isn't 32 bit!\n");
		return false;
	}
#endif

	if (pFileHeader->SizeOfOptionalHeader != sizeof(IMAGE_OPTIONAL_HEADER)) {
		printf("Dll file optional header invalid: %d / %zd!\n", pFileHeader->SizeOfOptionalHeader, sizeof(IMAGE_OPTIONAL_HEADER));
		return false;
	}

	/*PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER)&m_vData[pDosHeader->e_lfanew + sizeof(IMAGE_FILE_HEADER) + 4];
	if (pOptionalHeader->Magic != 0x010b) {
		printf("PE file optional header magic number wrong: %08x!\n", pOptionalHeader->Magic);
		return false;
	}*/

	return true;
}

struct LoadedFunction {
	std::string name;
	LPVOID address;
};

struct LoadedModule {
	std::wstring name;
	LPVOID address;
	std::vector<LoadedFunction> vFunctions;
};

class InjectableProcess {
public:
	InjectableProcess() : m_hProcess(0) {}
	InjectableProcess(HANDLE hProc) : m_hProcess(hProc) {}
	InjectableProcess(const InjectableProcess&) = delete;
	InjectableProcess(InjectableProcess&& o) : m_hProcess(o.m_hProcess), m_bIs64(o.m_bIs64), m_vModules(std::move(o.m_vModules)) { o.m_hProcess = 0; }

	InjectableProcess& operator=(const InjectableProcess&) = delete;
	InjectableProcess& operator=(InjectableProcess&& o) { m_hProcess = o.m_hProcess; m_bIs64 = o.m_bIs64; m_vModules = std::move(o.m_vModules); o.m_hProcess = 0; return *this; };

	~InjectableProcess() { if (m_hProcess && m_hProcess != INVALID_HANDLE_VALUE) { CloseHandle(m_hProcess); m_hProcess = 0; } }

	bool Init();

	bool Inject(InjectableDll&);

	static bool StaticInit();
	static bool GetProcess(std::wstring, InjectableProcess*);

public:
	HANDLE m_hProcess;
	bool m_bIs64;
	std::vector<LoadedModule> m_vModules;

	static HANDLE hNtdll;
	static PNtQueryInformationProcess NtQueryInformationProcess;
};

PNtQueryInformationProcess InjectableProcess::NtQueryInformationProcess;

bool InjectableProcess::Init() {

	BOOL isWow64;
	BOOL succ = IsWow64Process(m_hProcess, &isWow64);

	if (!succ) {
		printf("Can't determine process bitness!\n");
		return false;
	}

	m_bIs64 = !isWow64;

#ifdef _WIN64
	if (!m_bIs64) {
		printf("64 bit injector can only inject 64 bit processes!\n");
		return false;
	}
#else
	if (m_bIs64) {
		printf("32 bit injector can only inject 32 bit processes!\n");
		return false;
	}
#endif

	PROCESS_BASIC_INFORMATION pbi;
	ULONG rLen = 0;
	NTSTATUS s = NtQueryInformationProcess(m_hProcess, ProcessBasicInformation, &pbi, sizeof(PROCESS_BASIC_INFORMATION), &rLen);

	if (s) {
		printf("QueryInfo failed: %08x!\n", s);
		return false;
	}

	MEMORY_BASIC_INFORMATION i;
	if (!VirtualQueryEx(m_hProcess, (LPVOID)pbi.PebBaseAddress, &i, sizeof(MEMORY_BASIC_INFORMATION))) {

		printf("Query failed!\n");
		return false;
	}

	printf("%d\n", i.Protect);

	PEB peb;
	SIZE_T read;
	succ = ReadProcessMemory(m_hProcess, (LPVOID)pbi.PebBaseAddress, &peb, sizeof(PEB), &read);

	if (!succ) {
		printf("Loading PEB failed: %08x!\n", GetLastError());
		return false;
	}

	PEB_LDR_DATA ldr;
	succ = ReadProcessMemory(m_hProcess, (LPVOID)peb.Ldr, &ldr, sizeof(PEB_LDR_DATA), &read);

	if (!succ) {
		printf("Loading PEB_LDR_DATA failed!\n");
		return false;
	}

	LPVOID listEntry = (LPVOID)ldr.InMemoryOrderModuleList.Flink;

	while (listEntry) {

		LDR_DATA_TABLE_ENTRY e;
		succ = ReadProcessMemory(m_hProcess, (BYTE*)listEntry - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks), &e, sizeof(LDR_DATA_TABLE_ENTRY), &read);

		if (!succ) {
			printf("Loading LDR_DATA_TABLE_ENTRY failed!\n");
			return false;
		}

		if (!e.DllBase)
			break;

		LoadedModule m;
		m.name.resize(e.FullDllName.Length);
		m.address = e.DllBase;
		succ = ReadProcessMemory(m_hProcess, e.FullDllName.Buffer, &m.name[0], sizeof(WCHAR) * e.FullDllName.Length, &read);

		if (!succ) {
			printf("Loading name failed!\n");
			return false;
		}

		m.name = wcsrchr(m.name.c_str(), L'\\') + 1;
		
		m_vModules.push_back(m);

		listEntry = e.InMemoryOrderLinks.Flink;
	}

	BYTE functionName[256];
	for (auto it = m_vModules.begin(); it != m_vModules.end(); ++it) {

		BYTE* pModule = (BYTE*) it->address;
		IMAGE_DOS_HEADER dosHeader;

		succ = ReadProcessMemory(m_hProcess, pModule, &dosHeader, sizeof(IMAGE_DOS_HEADER), &read);
		if (!succ) {
			printf("Loading module dos header for %S failed!\n", it->name.c_str());
			return false;
		}

		IMAGE_OPTIONAL_HEADER optionalHeader;
		
		succ = ReadProcessMemory(m_hProcess, pModule + dosHeader.e_lfanew + sizeof(IMAGE_FILE_HEADER) + 4, &optionalHeader, sizeof(IMAGE_OPTIONAL_HEADER), &read);
		if (!succ) {
			printf("Loading module optional header for %S failed!\n", it->name.c_str());
			return false;
		}

		if (optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress == 0 || optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].Size == 0)
			continue;

		IMAGE_EXPORT_DIRECTORY exportDirectory;

		succ = ReadProcessMemory(m_hProcess, pModule + optionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress, &exportDirectory, sizeof(IMAGE_EXPORT_DIRECTORY), &read);
		if (!succ) {
			printf("Loading module export directory for %S failed!\n", it->name.c_str());
			return false;
		}

		std::vector<DWORD> vNames;
		vNames.resize(exportDirectory.NumberOfNames);
		std::vector<USHORT> vNameOrdinals;
		vNameOrdinals.resize(exportDirectory.NumberOfNames);
		std::vector<DWORD> vFunctions;
		vFunctions.resize(exportDirectory.NumberOfFunctions);

		if (vNames.size() > 0) {
			succ = ReadProcessMemory(m_hProcess, pModule + exportDirectory.AddressOfNames, &vNames[0], sizeof(DWORD) * vNames.size(), &read);
			if (!succ) {
				printf("Loading module name pointer table for %S failed!\n", it->name.c_str());
				return false;
			}
		}
		
		if (vNameOrdinals.size() > 0) {
			succ = ReadProcessMemory(m_hProcess, pModule + exportDirectory.AddressOfNameOrdinals, &vNameOrdinals[0], sizeof(USHORT) * vNameOrdinals.size(), &read);
			if (!succ) {
				printf("Loading module name ordinal pointer table for %S failed!\n", it->name.c_str());
				return false;
			}
		}

		if (vFunctions.size() > 0) {
			succ = ReadProcessMemory(m_hProcess, pModule + exportDirectory.AddressOfFunctions, &vFunctions[0], sizeof(DWORD) * vFunctions.size(), &read);
			if (!succ) {
				printf("Loading module function pointer table for %S failed!\n", it->name.c_str());
				return false;
			}
		}

		for (DWORD d = 0; d < exportDirectory.NumberOfNames; ++d) {

			succ = ReadProcessMemory(m_hProcess, pModule + vNames[d], functionName, 256, &read);
			if (!succ && GetLastError() != 0x12B) {
				printf("Loading module function name for %S failed!\n", it->name.c_str());
				return false;
			}

			LoadedFunction f;
			f.name = (char*) functionName;
			f.address = pModule + vFunctions[vNameOrdinals[d]];
			it->vFunctions.push_back(f);
		}
	}

	return true;
}

inline void upscale(std::vector<unsigned char> v, int l) {

	if (l < v.size())
		v.resize(l);
}

bool InjectableProcess::Inject(InjectableDll& dll) {
	
	PIMAGE_DOS_HEADER pDosHeader = (PIMAGE_DOS_HEADER) &dll.m_vData[0];
	PIMAGE_FILE_HEADER pFileHeader = (PIMAGE_FILE_HEADER) &dll.m_vData[pDosHeader->e_lfanew + 4];
	PIMAGE_OPTIONAL_HEADER pOptionalHeader = (PIMAGE_OPTIONAL_HEADER) (pFileHeader + 1);
	PIMAGE_SECTION_HEADER pSectionHeaders = (PIMAGE_SECTION_HEADER) (&dll.m_vData[pDosHeader->e_lfanew + sizeof(IMAGE_NT_HEADERS)]);

	struct SECTION {
		PIMAGE_SECTION_HEADER Header;
		std::vector<BYTE> Data;
	};

	std::vector<SECTION> remoteSections;
	
	LPBYTE pRemoteMemory = 0;
	LPBYTE dwMemoryOffset = 0;
	while (!pRemoteMemory) {
		pRemoteMemory = (LPBYTE)VirtualAllocEx(m_hProcess, (LPVOID)(pOptionalHeader->ImageBase + dwMemoryOffset), pOptionalHeader->SizeOfImage, MEM_RESERVE, PAGE_READWRITE);
		dwMemoryOffset += 0x10000;
	}

	printf("Allocated memory: %08zx\n", pRemoteMemory);

	printf("Sections: %d\n", pFileHeader->NumberOfSections);
	for (DWORD d = 0; d < pFileHeader->NumberOfSections; ++d) {

		SECTION s;
		s.Header = pSectionHeaders + d;

		if (s.Header->SizeOfRawData == 0)
			continue;

		s.Data.resize(s.Header->SizeOfRawData);
		CopyMemory(&s.Data[0], &dll.m_vData[s.Header->PointerToRawData], s.Header->SizeOfRawData);
		remoteSections.push_back(s);
	}

	auto getSectionDataPointer = [&remoteSections](RAV addr, RAV maxSize = 0) {

		for (DWORD i = 0; i < remoteSections.size(); ++i) {
			SECTION& s = remoteSections[i];
			if (addr >= s.Header->VirtualAddress && addr + maxSize < s.Header->VirtualAddress + s.Header->SizeOfRawData)
				return &s.Data[addr - s.Header->VirtualAddress];
		}

		return (LPBYTE) 0;
	};

	RAV dwDeltaImageBase = (RAV)(pRemoteMemory - pOptionalHeader->ImageBase);

	printf("Relocations...\n");
	PIMAGE_BASE_RELOCATION pReloc;
	for (DWORD dwRelocOffset = 0; dwRelocOffset < pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size; dwRelocOffset += pReloc->SizeOfBlock) {

		pReloc = (PIMAGE_BASE_RELOCATION)getSectionDataPointer(pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress + dwRelocOffset);

		struct RELOC_ENTRY {
			WORD offset : 12;
			WORD type : 4;
		};

		DWORD dwEntryCount = (pReloc->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(RELOC_ENTRY);
		RELOC_ENTRY* pEntries = (RELOC_ENTRY*)(pReloc + 1);

		for (DWORD i = 0; i < dwEntryCount; ++i) // Assume that type == 3
		{
			*(DWORD*)getSectionDataPointer(pReloc->VirtualAddress + pEntries[i].offset) += dwDeltaImageBase;
		}
	}

	printf("Imports...\n");

	PIMAGE_IMPORT_DESCRIPTOR pImports = (PIMAGE_IMPORT_DESCRIPTOR)getSectionDataPointer(pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress);

	while (pImports->Characteristics) {

		char* pName = (char*)getSectionDataPointer(pImports->Name);

		LoadedModule* pModule = 0;

		std::string s(pName);
		std::wstring w(s.length(), (wchar_t)0);
		std::copy(s.begin(), s.end(), w.begin());

		std::transform(w.begin(), w.end(), w.begin(), tolower);

		for(auto it = m_vModules.begin(); it < m_vModules.end(); ++it) {
		
			std::wstring currName = it->name;

			std::transform(currName.begin(), currName.end(), currName.begin(), tolower);

			printf("%S / %S\n", w.c_str(), currName.c_str());

			if (w.compare(currName) == 0) {
				pModule = it._Ptr;
				break;
			}
		}

		if (!pModule) {
			printf("Dependent library %s not loaded!\n", pName);
			return false;
		}

		PTR* psStart = (PTR*)getSectionDataPointer(pImports->OriginalFirstThunk);
		PTR* osStart = (PTR*)getSectionDataPointer(pImports->FirstThunk);

		DWORD off = 0;
		while (1) {
			PTR* ps = psStart + off;
			PTR* os = osStart + off;
			if (!*ps)
				break;
			PIMAGE_IMPORT_BY_NAME p = (PIMAGE_IMPORT_BY_NAME)getSectionDataPointer(*ps);

			*os = 0;

			for (auto it = pModule->vFunctions.begin(); it != pModule->vFunctions.end(); ++it) {

				if (it->name.compare(p->Name) == 0) {
					*os = (PTR) it->address;
					break;
				}
			}

			if (!*os) {
				printf("Unable to locate function %s\n", p->Name);
				return false;
			}
		
			//printf("Import: %s\n", p->Name);
			++off;
		}

		++pImports;
	}

	printf("Exports...\n");
	PIMAGE_EXPORT_DIRECTORY pExports = (PIMAGE_EXPORT_DIRECTORY)getSectionDataPointer(pOptionalHeader->DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT].VirtualAddress);
	DWORD* pNames = (DWORD*)getSectionDataPointer(pExports->AddressOfNames);
	USHORT* pOrdinals = (USHORT*)getSectionDataPointer(pExports->AddressOfNameOrdinals);
	DWORD* pFunctions = (DWORD*)getSectionDataPointer(pExports->AddressOfFunctions);

	RAV pEntryPoint = 0;

	for (DWORD d = 0; d < pExports->NumberOfNames; ++d) {
		LPSTR pName = (LPSTR)getSectionDataPointer(pNames[d]);
		USHORT o = (USHORT)pOrdinals[d];
		RAV pFunction = (RAV)pFunctions[o];
#ifdef _WIN64
		if (strcmp(pName, "DllThreadEntry") == 0)
#else
		if (strcmp(pName, "_DllThreadEntry@4") == 0)
#endif
			pEntryPoint = pFunction;
		printf("Export: %s\n", pName);
	}
	
	printf("Protections...\n");
	for (DWORD d = 0; d < remoteSections.size(); ++d) {

		SECTION& s = remoteSections[d];

		static const DWORD flags[8] = {
			PAGE_NOACCESS,
			PAGE_READWRITE,
			PAGE_READONLY,
			PAGE_READWRITE,
			PAGE_EXECUTE,
			PAGE_EXECUTE_READWRITE,
			PAGE_EXECUTE_READ,
			PAGE_EXECUTE_READWRITE
		};

		DWORD ind = 0;
		if (s.Header->Characteristics & IMAGE_SCN_MEM_EXECUTE)
			ind += 4;
		if (s.Header->Characteristics & IMAGE_SCN_MEM_READ)
			ind += 2;
		if (s.Header->Characteristics & IMAGE_SCN_MEM_WRITE)
			ind += 1;

		SIZE_T sWritten;

		printf("%zx - %zx\n", pRemoteMemory + s.Header->VirtualAddress, s.Header->SizeOfRawData);

		LPVOID remoteMem = VirtualAllocEx(m_hProcess, pRemoteMemory + s.Header->VirtualAddress, s.Header->SizeOfRawData, MEM_COMMIT, PAGE_READWRITE);
		printf("Commit: %zx - %d\n", remoteMem, GetLastError());
		BOOL b = WriteProcessMemory(m_hProcess, remoteMem, &s.Data[0], s.Header->SizeOfRawData, &sWritten);
		printf("Write: %d - %d\n", b, GetLastError());

		DWORD dwOld;
		b = VirtualProtectEx(m_hProcess, pRemoteMemory + s.Header->VirtualAddress, s.Header->SizeOfRawData, flags[ind], &dwOld);
		printf("Protect: %d - %d\n", b, GetLastError());
	}

	LPTHREAD_START_ROUTINE pStart = (LPTHREAD_START_ROUTINE)(pRemoteMemory + pEntryPoint);

	CreateRemoteThread(m_hProcess, 0, 0, pStart, (LPVOID)5, 0, 0);

	return true;
}

bool InjectableProcess::StaticInit() {

	HMODULE hNtdll = LoadLibraryW(L"Ntdll.dll");

	if (!hNtdll || hNtdll == INVALID_HANDLE_VALUE) {
		printf("Can't load Ntdll.dll!\n");
		return false;
	}

	NtQueryInformationProcess = (PNtQueryInformationProcess) GetProcAddress(hNtdll, "NtQueryInformationProcess");

	if (!NtQueryInformationProcess) {
		printf("Can't get NtQueryInformationProcess!\n");
		return false;
	}

	return true;
}


BOOL SetPrivilege(HANDLE hToken, LPCTSTR Privilege) {

	TOKEN_PRIVILEGES tp;
	LUID luid;
	TOKEN_PRIVILEGES tpPrevious;
	DWORD cbPrevious = sizeof(TOKEN_PRIVILEGES);
	
	if (!LookupPrivilegeValue(NULL, Privilege, &luid)) {
		printf("Privilege value lookup failed!\n");
		return FALSE;
	}

	tp.PrivilegeCount = 1;
	tp.Privileges[0].Luid = luid;
	tp.Privileges[0].Attributes = 0;

	AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), &tpPrevious, &cbPrevious);

	if (GetLastError() != ERROR_SUCCESS) {
	
		printf("First pass failed!\n");
		return FALSE;
	}
	
	tpPrevious.PrivilegeCount = 1;
	tpPrevious.Privileges[0].Luid = luid;
	tpPrevious.Privileges[0].Attributes |= SE_PRIVILEGE_ENABLED;
	
	AdjustTokenPrivileges(hToken, FALSE, &tpPrevious, cbPrevious, NULL, NULL);

	if (GetLastError() != ERROR_SUCCESS) {

		printf("Second pass failed!\n");
		return FALSE;
	}

	return TRUE;
}

bool EnableDebugPrivilege() {

	HANDLE hToken;
	if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) {
		printf("Couldn't open token!\n");
		return false;
	}

	// Debug power: SE_DEBUG_NAME
	if (!SetPrivilege(hToken, SE_DEBUG_NAME)) {
		printf("Unable to set debug token!\n");
		return false;
	}

	// System power: SE_TCB_NAME
	//if (!SetPrivilege(hToken, SE_TCB_NAME)) {
	//	printf("Unable to set system token!\n");
	//	return false;
	//}

	return true;
}

bool InjectableProcess::GetProcess(std::wstring name, InjectableProcess* pProc) {

	std::vector<DWORD> vProcIds;
	vProcIds.resize(256);

	DWORD ret;
	while (EnumProcesses(&vProcIds[0], (DWORD) vProcIds.size() * sizeof(DWORD), &ret)) {

		DWORD count = ret / sizeof(DWORD);
		if (count < vProcIds.size()) {
			vProcIds.resize(count);
			break;
		}
		vProcIds.resize(vProcIds.size() * 2);
	}
	
	TCHAR nameBuf[MAX_PATH];

	HANDLE hProcess = INVALID_HANDLE_VALUE;
	for (auto it = vProcIds.begin(); it != vProcIds.end(); ++it) {

		if (!*it)
			continue;

		hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, *it);

		if (hProcess) {

			if (GetModuleFileNameExW(hProcess, 0, nameBuf, MAX_PATH)) {
				if (wcscmp(wcsrchr(nameBuf, '\\') + 1, name.c_str()) == 0)
					break;
			}

			CloseHandle(hProcess);
			hProcess = INVALID_HANDLE_VALUE;
		}
	}

	vProcIds.clear();

	if (!hProcess || hProcess == INVALID_HANDLE_VALUE) {
		printf("Couldn't find process \"%S\"!\n", name.c_str());
		return false;
	}

	*pProc = InjectableProcess(hProcess);
	return true;
}

const WCHAR* PROCESS_NAME = L"TslGame.exe";

void Run() {

	if (!EnableDebugPrivilege()) {
		printf("Can't enable debug privileges!\n");
		return;
	}

	if (!InjectableProcess::StaticInit())
		return;

	InjectableProcess p;
	if (!InjectableProcess::GetProcess(PROCESS_NAME, &p))
		return;

	if (!p.Init())
		return;

	InjectableDll dll;
#ifdef _WIN64
	if (!dll.Load(L"../x64/Debug/PUBGD.dll"))
#else
	if (!dll.Load(L"../Debug/PUBGD.dll"))
#endif
		return;

	p.Inject(dll);
}

int CALLBACK WinMain(HINSTANCE, HINSTANCE, PSTR, int) {

	AllocConsole();
	freopen("CONOUT$", "w", stdout);

	{
		Run();
	}

	system("pause");

	return 0;
}