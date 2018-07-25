// dllmain.cpp : Defines the entry point for the DLL application.
#include "stdafx.h"
#include <stdio.h>
#include <stdlib.h>
#include "util.h"

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
		println("input file not found");
		return 1;
	}
	CString lines;
	static const size_t BUFF_SIZE = 1024 * 4;
	char buffer[BUFF_SIZE] = {};
	while (::fgets(buffer, BUFF_SIZE, file) != NULL)
	{
		CString str(buffer);
		str.Trim();
		lines += str;
		lines += '\n';
	}
	::fclose(file);

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
			work();
			break;
		case DLL_THREAD_ATTACH:
			//println("DLLMain DLL_THREAD_ATTACH called.");
			//work();
			break;
		case DLL_THREAD_DETACH:
			//println("DLLMain DLL_THREAD_DETACH called.");
			break;
		case DLL_PROCESS_DETACH:
			//println("DLLMain DLL_PROCESS_DETACH called.");
			::DeleteCriticalSection(&g_cs);
			break;
		}
	}
	catch (...) {

	}

    return TRUE;
}

