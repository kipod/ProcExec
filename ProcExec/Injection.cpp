#include "stdafx.h"
#include "Injection.h"
#include <Psapi.h>
#include <stdint.h>
#include "util.h"
#include <logging.h>

int InjectInProc(HANDLE hProc, HMODULE &hLibModule, DWORD &dwTid)
{

	//Get address of the LoadLibrary function.
	LPVOID addr = ::GetProcAddress(::GetModuleHandle(L"kernel32.dll"), "LoadLibraryW");
	if (addr == nullptr) {
		//::perror("Error: the LoadLibraryA function was not found inside kernel32.dll library.");
		LOG("ERROR: the LoadLibraryA function was not found inside kernel32.dll library");
		return 3;
	}

	CString sPathToInjectDll = PE::pathToInjectDll();
	// Allocate new memory region inside the process's address space.
	size_t memSize = sPathToInjectDll.GetLength() * sizeof(wchar_t) + 2;
	LPVOID arg = ::VirtualAllocEx(hProc, nullptr, memSize, MEM_RESERVE | MEM_COMMIT, PAGE_READWRITE);
	if (arg == nullptr) {
		//::perror("Error: the memory could not be allocated inside the chosen process.");
		LOG("ERROR: the memory could not be allocated inside the chosen process");
		return 4;
	}

	// Write the argument to LoadLibraryW to the process's newly allocated memory region.
	if (0 == ::WriteProcessMemory(hProc, arg, LPCTSTR(sPathToInjectDll), memSize, nullptr)) {
		//printf("Error: there was no bytes written to the process's address space.\n");
		LOG("ERROR: there was no bytes written to the process's address space");
		return 5;
	}

	// Inject our DLL into the process's address space.
	HANDLE hThread = ::CreateRemoteThread(hProc, nullptr, 0, (LPTHREAD_START_ROUTINE)addr, arg, 0, nullptr);
	if (hThread == nullptr) {
		//printf("Error: the remote thread could not be created.\n");
		LOG("ERROR: the remote thread could not be created");
		return 6;
	}

	::WaitForSingleObject(hThread, INFINITE);
	// Get handle of the loaded module	
	hLibModule = GetModuleByName(hProc, PE::INJECT_DLL);

	::CloseHandle(hThread);

	FILE *file = nullptr;
	::fopen_s(&file, PE::pathToTidFile(), "r");
	if (file)
	{
		fscanf_s(file, "%d", &dwTid);
		::fclose(file);
	}

	::VirtualFreeEx(hProc, arg, memSize, MEM_RELEASE);
	
	return 0;
}

BOOL UnloadInjectedModule(HANDLE hProc, HMODULE hModule)
{
	auto hThread = ::CreateRemoteThread(hProc, nullptr, 0,
		(LPTHREAD_START_ROUTINE) ::GetProcAddress(::GetModuleHandle(L"kernel32.dll"),
			"FreeLibrary"),
			(void*)hModule, 0, nullptr);
	::WaitForSingleObject(hThread, INFINITE);

	DWORD dwResult = 0;
	::GetExitCodeThread(hThread, &dwResult);

	// Clean up
	::CloseHandle(hThread);
	return BOOL(dwResult);
}

HMODULE GetModuleByName(HANDLE hProc, LPCWSTR moduleName)
{
	HMODULE hModule = nullptr;
	const size_t MAX_NUM_MODULES = 1024*4;
	HMODULE allModules[MAX_NUM_MODULES] = {};
	DWORD out_size = 0;
	if (FALSE != ::EnumProcessModulesEx(hProc, allModules, MAX_NUM_MODULES * sizeof(HMODULE), &out_size, LIST_MODULES_ALL))
	{
		size_t size = out_size / sizeof(HMODULE);
		MODULEINFO modinfo = { 0 };
		for (size_t i = 0; i < size; ++i)
		{
			auto hm = allModules[i];
			WCHAR buf[MAX_PATH] = {};
			::GetModuleFileNameExW(hProc, hm, buf, MAX_PATH);
			CStringW name(buf);
			name = name.MakeLower();
			if (name.MakeLower().Find(moduleName) != -1)
			{
				hModule = hm;
				break;
			}
		}
	}
	return hModule;
}

void ResExtract(WORD wResId, CString strOutputPath)
{ //example: Extract(IDB_BITMAP1, "Redrose.bmp");
	HRSRC hrsrc = ::FindResource(nullptr, MAKEINTRESOURCE(wResId), RT_RCDATA);
	if (hrsrc)
	{
		HGLOBAL hLoaded = ::LoadResource(nullptr, hrsrc);
		LPVOID lpLock = ::LockResource(hLoaded);
		DWORD dwSize = ::SizeofResource(nullptr, hrsrc);
		CHandle hFile(::CreateFile(strOutputPath, GENERIC_WRITE, 0, nullptr, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr));
		DWORD dwByteWritten;
		::WriteFile(hFile, lpLock, dwSize, &dwByteWritten, nullptr);
		::FreeResource(hLoaded);
	}
	
}