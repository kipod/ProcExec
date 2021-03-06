// ProcExec.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "ProcExec.h"
#include <atlstr.h>
#include "Injection.h"
#include "util.h"
#include "logging.h"

// Global Variables:
HINSTANCE hInst = nullptr;                                // current instance

class AppLock {
public:
	AppLock()
		: m_mutex(::CreateMutex(nullptr, TRUE, L"Global\\__PROCEXEC_MUTEX__"))
	{
		::WaitForSingleObject(m_mutex, INFINITE);
	}
	~AppLock() { ::ReleaseMutex(m_mutex); }
private:
	CHandle m_mutex;
};

int main(int argc, char* argv[])
{
	USES_CONVERSION;
	LOG("started %s with %d arguments", A2W(argv[0]), argc-1);
	if (argc < 2)
	{
		LOG("ERROR: give me what to run...");
		::perror("give me what to run...");
		return 10;
	}
	LOGA("first argument '%s'", argv[1]);
	AppLock __lock_single_app_instance;
	FILE *file = nullptr;
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
		LOG("ERROR: cannot create input file...")
		perror("cannot create input file...");
		return 11;
	}

	DWORD dwPid = 0;
	if (!PE::GetProcessByExeName(&dwPid/*, L"NOTEPAD.EXE"*/))
	{
		LOG("ERROR: cannot found explorer.exe")
		::perror("cannot found explorer.exe");
		return 1;
	}

	// Get process handle passing in the process ID.
	HANDLE hProc = ::OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	if (hProc == nullptr) {
		LOG("ERROR: the specified process couldn't be found")
		::perror("Error: the specified process couldn't be found.");
		return 2;
	}

	ResExtract(IDR_BIN_DLL, PE::pathToInjectDll());
	
	HMODULE hMod = nullptr;
	DWORD dwTid = 0; // injected thread ID
	int err = InjectInProc(hProc, hMod, dwTid);
	if (err != 0)
	{
		return err;
	}

	if (dwTid)
	{
		CHandle workThread(::OpenThread(SYNCHRONIZE, FALSE, dwTid));
		LOG("Waiting for thread %d", dwTid);
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
		while (::fgets(buffer, BUFF_SIZE, file) != nullptr)
		{
			puts(buffer);
		}
		::fclose(file);
	}
	::DeleteFileA(PE::pathToInputFile());
	::DeleteFileA(PE::pathToOutputFile());
	::DeleteFile(PE::pathToInjectDll());

	LOG("INFO: OK")	
	return 0;
}
