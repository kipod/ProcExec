// ProcExec.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "ProcExec.h"
#include <tlhelp32.h>
#include <atlstr.h>
#include "Injection.h"
#include "util.h"

// Global Variables:
HINSTANCE hInst = nullptr;                                // current instance

class AppLock {
public:
	AppLock()
		: m_mutex(::CreateMutex(NULL, TRUE, L"Global\\__PROCEXEC_MUTEX__"))
	{
		::WaitForSingleObject(m_mutex, INFINITE);
	}
	~AppLock() { ::ReleaseMutex(m_mutex); }
private:
	CHandle m_mutex;
};

bool GetProcessByExeName(DWORD* Pid, LPCWSTR ExeName = L"EXPLORER.EXE")
{
	HANDLE hProcessSnap = nullptr;
	hProcessSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPALL, NULL);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		//::MessageBoxW(NULL, L"Cannot get Processes snapshot", L"Error", MB_OK | MB_ICONWARNING | MB_SYSTEMMODAL);
		*Pid = 0;
		return false;
	}

	PROCESSENTRY32W pe32 = { 0 };
	pe32.dwSize = sizeof(PROCESSENTRY32W);
	CStringW temp = L"";

	if (Process32FirstW(hProcessSnap, &pe32)) temp = pe32.szExeFile;
	if (temp.MakeUpper().Find(ExeName) != -1)
	{
		*Pid = pe32.th32ProcessID;
		::CloseHandle(hProcessSnap);
		return true;
	}
	pe32.dwSize = sizeof(PROCESSENTRY32W);

	while (::Process32NextW(hProcessSnap, &pe32))
	{
		temp = pe32.szExeFile;
		if (temp.MakeUpper().Find(ExeName) != -1)
		{
			*Pid = pe32.th32ProcessID;
			::CloseHandle(hProcessSnap);
			return true;
		}
		pe32.dwSize = sizeof(PROCESSENTRY32W);
	}

	::CloseHandle(hProcessSnap);
	*Pid = 0;
	return false;
}

int main(int argc, char* argv[])
{
	if (argc < 2)
	{
		::perror("give me what to run...");
		return 10;
	}
	
	AppLock __lock_single_app_instance;
	FILE *file = NULL;
	::fopen_s(&file, PE::pathToInputFile(), "w");
	if (file)
	{
		for (int i = 1; i < argc; ++i)
		{
			fprintf(file, argv[i]);
			fprintf(file, "\n");
		}
		::fclose(file);
	}
	else {
		perror("cannot create input file...");
		return 11;
	}

	DWORD dwPid = 0;
	if (!GetProcessByExeName(&dwPid))
	{
		::perror("cannot found explorer.exe");
		return 1;
	}

	// Get process handle passing in the process ID.
	HANDLE hProc = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	if (hProc == NULL) {
		::perror("Error: the specified process couldn't be found.");
		return 2;
	}

	ResExtract(IDR_BIN_DLL, INJECT_DLL);
	
	HMODULE hMod = NULL;
	DWORD dwTid = 0; // injected thread ID
	int err = InjectInProc(hProc, hMod, dwTid);
	if (err != 0)
	{
		return err;
	}

	if (dwTid)
	{
		CHandle workThread(::OpenThread(SYNCHRONIZE, FALSE, dwTid));
		::WaitForSingleObject(workThread, INFINITE);
	}

	UnloadInjectedModule(hProc, hMod);

	// Close the handle to the process, because we've already injected the DLL.
	::CloseHandle(hProc);

	// Print output file
	::fopen_s(&file, PE::pathToOutputFile(), "r");
	if (file)
	{
		static const size_t BUFF_SIZE = 1024 * 4;
		char buffer[BUFF_SIZE] = {};
		while (::fgets(buffer, BUFF_SIZE, file) != NULL)
		{
			puts(buffer);
		}
		::fclose(file);
	}
	::DeleteFileA(PE::pathToInputFile());
	::DeleteFileA(PE::pathToOutputFile());
	
	return 0;
}
