#include "stdafx.h"
#include "util.h"
#include <stdlib.h>
#include <future>
#include <sstream>
#include <tlhelp32.h>
#include <logging.h>

namespace PE {

LPCWSTR INJECT_DLL = L"inject.dll";

static const char TimeoutErrorMessage[] = "Error: Timeout";

CStringA Env(LPCSTR varName)
{
	size_t _RequiredCount;
	::getenv_s(&_RequiredCount, nullptr, 0, "LOCALAPPDATA");
	CStringA buffer;
	::getenv_s(&_RequiredCount, buffer.GetBuffer(int(_RequiredCount)), _RequiredCount, "LOCALAPPDATA");
	buffer.ReleaseBuffer();
	return buffer;
}

namespace {

struct StdStreamData {
	StdStreamData(HANDLE hStream)
		: hStream(hStream) {}
	CHandle hStream;
	std::vector<CString> lines;
};

//************************************
// Function:  StdInputWriteThreadProc
// FullName:  PE::StdInputWriteThreadProc
// Returns:   DWORD
// Qualifier: writes lines into standard input stream of controlled process
// Parameter: LPVOID pData
//************************************
DWORD WINAPI StdInputWriteThreadProc(LPVOID pData)
{
	LOG("StdInputWriteThreadProc: started");
	auto *p = reinterpret_cast<StdStreamData *>(pData);
	auto &lines = p->lines;
	HANDLE hFile = p->hStream;
	for (auto& line : lines)
	{
		DWORD nWritten = 0;
		DWORD nSize = line.GetLength();
		CT2A tmp(line.GetBuffer(nSize));
		LPCSTR buffer = tmp;
		::WriteFile(hFile, buffer, nSize, &nWritten, nullptr);
		::WriteFile(hFile, "\r\n", 2, &nWritten, nullptr);
		LOG("StdInputWriteThreadProc: write: '%s'", line);
	}
	p->hStream.Close();
	LOG("StdInputWriteThreadProc: finished");
	return 0;
}

//************************************
// Function:  StdOutputReadThreadProc
// FullName:  PE::StdOutputReadThreadProc
// Returns:   DWORD
// Qualifier: read lines from standard output of the controlled process and writes them into string buffer
// Parameter: LPVOID pData
//************************************
DWORD WINAPI StdOutputReadThreadProc(LPVOID pData)
{
	LOG("StdOutputReadThreadProc started");
	auto *p = reinterpret_cast<StdStreamData *>(pData);

	const size_t BUF_SIZE = 8192;
	CHAR lpBuffer[BUF_SIZE] = { 0 };
	DWORD nBytesRead = 0;

	auto &lines = p->lines;
	HANDLE hFile = p->hStream;
	while(FALSE != ::ReadFile(hFile, lpBuffer, BUF_SIZE,
		&nBytesRead, nullptr))
	{
		WCHAR wcpBuffer[BUF_SIZE] = { 0 };
		::MultiByteToWideChar(CP_OEMCP, 0, lpBuffer, nBytesRead, wcpBuffer, nBytesRead);
		std::wstring sBuffer(wcpBuffer);
		std::wstringstream ss(sBuffer);
		std::wstring line;
		while (std::getline(ss, line))
		{
			CStringW str(line.c_str());
			str.Trim();
			lines.push_back(str);
			LOG("Std Out: %s", line.c_str());
		}
	}

	LOG("StdOutputReadThreadProc finished");
	return 0;
}

} // namespace

CString PowershellExec(std::vector<CString> scriptLines, DWORD dwTimeout)
{
	CString result;

	CString command = TEXT("powershell -Command -");

	//////////////////////////////////////////////////////////////////////////
	//

	CHandle hOutputReadTmp, hOutputRead, hOutputWrite;
	CHandle hInputWriteTmp, hInputRead, hInputWrite;
	CHandle hErrorWrite;
	SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES),  nullptr, TRUE };

	DWORD dwPipeSize = 0;

	// Create the child output pipe.
	if (FALSE == ::CreatePipe(&hOutputReadTmp.m_h, &hOutputWrite.m_h, &sa, dwPipeSize))
	{
		LOG("ERROR: Can't create output pipe");
		return "Error: Can't create pipe";
	}

	// Create a duplicate of the output write handle for the std error
	// write handle. This is necessary in case the child application
	// closes one of its std output handles.
	if (FALSE == ::DuplicateHandle(GetCurrentProcess(), hOutputWrite,
		GetCurrentProcess(), &hErrorWrite.m_h, 0,
		TRUE, DUPLICATE_SAME_ACCESS))
	{
		LOG("ERROR: Cannot duplicate handle for output pipe");
		return "Error: Can't DuplicateHandle";
	}

	// Create the child input pipe.
	if (FALSE == ::CreatePipe(&hInputRead.m_h, &hInputWriteTmp.m_h, &sa, dwPipeSize))
	{
		LOG("ERROR: Can't create input pipe");
		return "Error: Can't create pipe";
	}

	// Create new output read handle and the input write handles. Set
	// the Properties to FALSE. Otherwise, the child inherits the
	// properties and, as a result, non-close able handles to the pipes
	// are created.
	if (FALSE == ::DuplicateHandle(GetCurrentProcess(), hOutputReadTmp,
		GetCurrentProcess(),
		&hOutputRead.m_h, // Address of new handle.
		0, FALSE, // Make it non-inheritable.
		DUPLICATE_SAME_ACCESS))
	{
		LOG("ERROR: Can't create input pipe");
		return "Error: Can't DuplicateHandle";
	}

	if (FALSE == ::DuplicateHandle(GetCurrentProcess(), hInputWriteTmp,
		GetCurrentProcess(),
		&hInputWrite.m_h, // Address of new handle.
		0, FALSE, // Make it non-inheritable.
		DUPLICATE_SAME_ACCESS))
	{
		LOG("ERROR: Cannot duplicate handle for input pipe");
		return "Error: Can't DuplicateHandle";
	}


	// Close inheritable copies of the handles you do not want to be
	// inherited.
	hOutputReadTmp.Close();
	hInputWriteTmp.Close();

	//////////////////////////////////////////////////////////////////////////
	CHandle hProcess;

	PROCESS_INFORMATION pi;
	::ZeroMemory(&pi, sizeof(pi));

	STARTUPINFO si;
	::ZeroMemory(&si, sizeof(si));
	si.cb = sizeof(si);
	si.wShowWindow = SW_HIDE;
	si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
	si.hStdInput = hInputRead;
	si.hStdOutput = hOutputWrite;
	si.hStdError = hErrorWrite;

	LOG("INFO: Start process: %s", command);
	if (FALSE != ::CreateProcessAsUser(nullptr,
		nullptr,
		command.GetBuffer(command.GetLength() + 1),
		nullptr,
		nullptr,
		TRUE,
		NORMAL_PRIORITY_CLASS,
		nullptr,
		nullptr,
		&si,
		&pi
	))
	{
		::CloseHandle(pi.hThread);
		hProcess.Attach(pi.hProcess);

		//////////////////////////////////////////////////////////////////////////
		// Write input
		StdStreamData inputData(hInputWrite.Detach());
		inputData.lines = scriptLines;
		CHandle writeThread(::CreateThread(nullptr, 0, StdInputWriteThreadProc, &inputData, 0, nullptr));
		//////////////////////////////////////////////////////////////////////////

		//////////////////////////////////////////////////////////////////////////
		// Read output
		StdStreamData ouputData(hOutputRead.Detach());
		CHandle readThread(::CreateThread(nullptr, 0, StdOutputReadThreadProc, &ouputData, 0, nullptr));
		::SetThreadPriority(readThread, THREAD_PRIORITY_HIGHEST);
		//////////////////////////////////////////////////////////////////////////

		//////////////////////////////////////////////////////////////////////////
// 		DWORD nNumberOfBytesWritten = 0;
// 		::WriteFile(hOutputWrite, "\n", 1, &nNumberOfBytesWritten, nullptr);
		//////////////////////////////////////////////////////////////////////////

		::WaitForSingleObject(writeThread, INFINITE);

		bool timeout = (WAIT_TIMEOUT == ::WaitForSingleObject(hProcess, dwTimeout));
		if (!timeout)
		{
			LOG("INFO: PowershellExec: Process finished");
 			hProcess.Close();
 			::FlushFileBuffers(hOutputWrite);
// 			hOutputWrite.Close();
// 			::CancelIo(ouputData.hStream);
// 			::CloseHandle(ouputData.hStream);
			CancelSynchronousIo(readThread);
			LOG("INFO: Wait for reading thread");
			::WaitForSingleObject(readThread, INFINITE);
			auto &lines = ouputData.lines;
			if (!lines.empty())
			{
				result = *(lines.rbegin());
			}
			else
			{
#ifdef _DEBUG
				::OutputDebugStringW(L"Output is empty!");
				::OutputDebugStringW(L"\n");
#endif
			}
			//////////////////////////////////////////////////////////////////////////
		}
		else
		{
			result = TimeoutErrorMessage;
		}

		::WaitForSingleObject(readThread, INFINITE);
	}

	return result;
}

CStringA pathToInputFile()
{
	static CStringA path;
	if (path.IsEmpty())
	{
		path.Format("%s\\prosexec.in.ps1", Env("LOCALAPPDATA"));
	}
	return path;
}

CStringA pathToOutputFile()
{
	static CStringA path;
	if (path.IsEmpty())
	{
		path.Format("%s\\prosexec.out.log", Env("LOCALAPPDATA"));
	}
	return path;
}

CStringA pathToTidFile()
{
	static CStringA path;
	if (path.IsEmpty())
	{
		path.Format("%s\\prosexec.tid", Env("LOCALAPPDATA"));
	}
	return path;
}

CString pathToInjectDll()
{
	static CString path;
	if (path.IsEmpty())
	{
		const size_t PAGE_SIZE = 4096;
		WCHAR injectDLL[PAGE_SIZE] = {};
		::GetModuleFileName(nullptr, injectDLL, PAGE_SIZE);
		path = injectDLL;
		path = path.MakeLower();
		path.Replace(L"procexec.exe", INJECT_DLL);
		path.ReleaseBuffer();

	}
	return path;
}

bool GetProcessByExeName(DWORD* Pid, LPCWSTR ExeName)
{
	HANDLE hProcessSnap = nullptr;
	hProcessSnap = ::CreateToolhelp32Snapshot(TH32CS_SNAPALL, 0);
	if (hProcessSnap == INVALID_HANDLE_VALUE)
	{
		//::MessageBoxW(nullptr, L"Cannot get Processes snapshot", L"Error", MB_OK | MB_ICONWARNING | MB_SYSTEMMODAL);
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


} // namespace PE