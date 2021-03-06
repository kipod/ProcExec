// dllmain.cpp : Defines the entry point for the DLL application.

#include "stdafx.h"
#include <stdio.h>
#include <stdlib.h>
#include "util.h"
#include <logging.h>

CStringA g_sPathToOutput;
CRITICAL_SECTION g_cs = {};
HMODULE g_hModule = NULL;


void println(const char *str) {
	::EnterCriticalSection(&g_cs);
	FILE *file = nullptr;
	::fopen_s(&file, PE::pathToOutputFile(), "a");
	if (file)
	{
		fprintf(file, str);
		fprintf(file, "\n");
		::fclose(file);
	}
	::LeaveCriticalSection(&g_cs);
}

DWORD WINAPI doWork(LPVOID)
{
	FILE *file = nullptr;
	::fopen_s(&file, PE::pathToInputFile(), "r");
	if (!file)
	{
		LOG("ERROR: input file not found");
		println("input file not found");
		return 1;
	}
	std::vector<CString> lines;
	const size_t BUFF_SIZE = 1024 * 4;
	char buffer[BUFF_SIZE] = {};
	while (::fgets(buffer, BUFF_SIZE, file) != NULL)
	{
		CString str(buffer);
		str.Trim();
		lines.push_back(str);
	}
	::fclose(file);

	LOG("INFO: call PowershellExec with lines.size=%d", lines.size());
	println(CStringA(PE::PowershellExec(lines)));
	return 0;
}

void work()
{
	DWORD dwTid = 0;
	::CloseHandle(::CreateThread(NULL, 0, doWork, NULL, 0, &dwTid));
	FILE *file = nullptr;
	::fopen_s(&file, PE::pathToTidFile(), "w");
	if (file)
	{
		fprintf(file, "%d", dwTid);
		::fclose(file);
	}
}


BOOL APIENTRY DllMain( HMODULE hModule,
                       DWORD  ul_reason_for_call,
                       LPVOID lpReserved
                     )
{
	try {
		switch (ul_reason_for_call)
		{
		case DLL_PROCESS_ATTACH:
			g_hModule = hModule;
			::InitializeCriticalSection(&g_cs);
			g_sPathToOutput = PE::pathToOutputFile();
			//println("DLLMain DLL_PROCESS_ATTACH called.");
			LOG("inject.dll: DLL_PROCESS_ATTACH");
			work();
			break;
		case DLL_THREAD_ATTACH:
			//println("DLLMain DLL_THREAD_ATTACH called.");
			//work();
			LOG("inject.dll: DLL_THREAD_ATTACH");
			break;
		case DLL_THREAD_DETACH:
			//println("DLLMain DLL_THREAD_DETACH called.");
			LOG("inject.dll: DLL_THREAD_DETACH");
			break;
		case DLL_PROCESS_DETACH:
			//println("DLLMain DLL_PROCESS_DETACH called.");
			LOG("inject.dll: DLL_PROCESS_DETACH");
			::DeleteCriticalSection(&g_cs);
			break;
		}
	}
	catch (...) {

	}

    return TRUE;
}

