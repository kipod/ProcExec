#include "stdafx.h"
#include "util.h"
#include <stdlib.h>
#include <future>
#include <sstream>

namespace PE {

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
struct StdInputData {
	StdInputData(const CString& lines, CHandle& hInputWrite)
		: lines(lines)
		, hInputWrite(hInputWrite)
	{}
	CString lines;
	CHandle hInputWrite;
};

DWORD WINAPI StdInputWriterThreadProc(LPVOID pData)
{
	auto *p = reinterpret_cast<StdInputData *>(pData);
	DWORD nWritten = 0;
	CT2A tmp(p->lines.GetBuffer(p->lines.GetLength()));
	LPCSTR buffer = tmp;
	DWORD nSize = p->lines.GetLength();
	::WriteFile(p->hInputWrite, buffer, nSize, &nWritten, NULL);
	::WriteFile(p->hInputWrite, "\r\n", 2, &nWritten, NULL);
	p->hInputWrite.Close();
	delete p;
	return 0;
}
}

CString PowershellExec(CString scriptLines, DWORD dwTimeout)
{
	CString result;

	//CString command = TEXT("powershell -Version 2.0 -Command -");
	CString command = TEXT("powershell -Command -");

	//////////////////////////////////////////////////////////////////////////
	//

	CHandle hOutputReadTmp, hOutputRead, hOutputWrite;
	CHandle hInputWriteTmp, hInputRead, hInputWrite;
	CHandle hErrorWrite;
	SECURITY_ATTRIBUTES sa = { sizeof(SECURITY_ATTRIBUTES),  NULL, TRUE };

	DWORD dwPipeSize = 0;

	// Create the child output pipe.
	if (FALSE == ::CreatePipe(&hOutputReadTmp.m_h, &hOutputWrite.m_h, &sa, dwPipeSize))
	{
		return "Error: Can't create pipe";
	}

	// Create a duplicate of the output write handle for the std error
	// write handle. This is necessary in case the child application
	// closes one of its std output handles.
	if (FALSE == ::DuplicateHandle(GetCurrentProcess(), hOutputWrite,
		GetCurrentProcess(), &hErrorWrite.m_h, 0,
		TRUE, DUPLICATE_SAME_ACCESS))
	{
		return "Error: Can't DuplicateHandle";
	}

	// Create the child input pipe.
	if (FALSE == ::CreatePipe(&hInputRead.m_h, &hInputWriteTmp.m_h, &sa, dwPipeSize))
	{
		return "Error: Can't create pipe";
	}

	// Create new output read handle and the input write handles. Set
	// the Properties to FALSE. Otherwise, the child inherits the
	// properties and, as a result, non-closeable handles to the pipes
	// are created.
	if (FALSE == ::DuplicateHandle(GetCurrentProcess(), hOutputReadTmp,
		GetCurrentProcess(),
		&hOutputRead.m_h, // Address of new handle.
		0, FALSE, // Make it uninheritable.
		DUPLICATE_SAME_ACCESS))
	{
		return "Error: Can't DuplicateHandle";
	}

	if (FALSE == ::DuplicateHandle(GetCurrentProcess(), hInputWriteTmp,
		GetCurrentProcess(),
		&hInputWrite.m_h, // Address of new handle.
		0, FALSE, // Make it uninheritable.
		DUPLICATE_SAME_ACCESS))
	{
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

	if (FALSE != ::CreateProcessAsUser(NULL,
		NULL,
		command.GetBuffer(command.GetLength() + 1),
		NULL,
		NULL,
		TRUE,
		NORMAL_PRIORITY_CLASS,
		NULL,
		NULL,
		&si,
		&pi
	))
	{
		::CloseHandle(pi.hThread);
		hProcess.Attach(pi.hProcess);

		//////////////////////////////////////////////////////////////////////////
		// Write input
		auto* pData = new StdInputData(scriptLines, hInputWrite);
		CHandle writeThread(::CreateThread(NULL, 0, StdInputWriterThreadProc, pData, 0, NULL));
// 		std::async(std::launch::async, [&] {
// 			DWORD nWritten = 0;
// 			CT2A tmp(scriptLines.GetBuffer(scriptLines.GetLength()));
// 			LPCSTR buffer = tmp;
// 			DWORD nSize = scriptLines.GetLength();
// 			::WriteFile(hInputWrite, buffer, nSize, &nWritten, NULL);
// 			::WriteFile(hInputWrite, "\r\n", 2, &nWritten, NULL);
// 			hInputWrite.Close();
// 		});
		//////////////////////////////////////////////////////////////////////////


		bool timeout = (WAIT_TIMEOUT == ::WaitForSingleObject(hProcess, dwTimeout));
		if (!timeout)
		{
			//////////////////////////////////////////////////////////////////////////
			// Read Output
			//LOG_MESSAGE(TME_VERBOSE, "Read script output");
			CHAR lpBuffer[8192] = { 0 };
			DWORD nBytesRead = 0;

			std::vector<CString> lines;

			//CHandle hReadDoneEvent(::CreateEvent(NULL, TRUE, FALSE, NULL));
			DWORD nNumberOfBytesWritten = 0;
			::WriteFile(hOutputWrite, "\n", 1, &nNumberOfBytesWritten, NULL);
			/////////////////////////////////////////////////////////////////////////
			// Wait Timeout
// 			std::thread wait_timeout_thread([&hReadDoneEvent, &hOutputWrite, &dwTimeout] {
// 				if (WAIT_TIMEOUT == ::WaitForSingleObject(hReadDoneEvent, dwTimeout))
// 				{
// 					::SetLastError(ERROR_TIMEOUT);
// 					static const DWORD nNumberOfBytesToWrite = sizeof(TimeoutErrorMessage);
// 					DWORD nNumberOfBytesWritten = 0;
// 					::WriteFile(hOutputWrite, TimeoutErrorMessage, nNumberOfBytesToWrite, &nNumberOfBytesWritten, NULL);
// 					hOutputWrite.Close();
// 				}
// 			});
			//wait_timeout_thread.detach();
			//////////////////////////////////////////////////////////////////////////

			if (FALSE == ::ReadFile(hOutputRead, lpBuffer, _countof(lpBuffer),
				&nBytesRead, NULL) || !nBytesRead)
			{
				//LOG_MESSAGE(TME_ERROR, "Can't read output");
				return "Error: Can't read output";
			}
			//::SetEvent(hReadDoneEvent);

			//wait_timeout_thread.join();
			//hReadDoneEvent.Close();

			WCHAR wcpBuffer[_countof(lpBuffer)] = { 0 };
			::MultiByteToWideChar(CP_OEMCP, 0, lpBuffer, nBytesRead, wcpBuffer, nBytesRead);
			//CString s(wcpBuffer);
			std::wstring sBuffer(wcpBuffer);
			std::wstringstream ss(sBuffer);
			std::wstring line;
			while (std::getline(ss, line))
			{
 				CStringW str(line.c_str());
				str.Trim();
				if (!line.empty()) lines.push_back(str);
				//LOG_MESSAGE(TME_VERBOSE, "%S", line.c_str());
#ifdef _DEBUG
				::OutputDebugStringW(line.c_str());
				::OutputDebugStringW(L"\n");
#endif
			}

			if (!lines.empty())
			{
				result = *(lines.rbegin());
			}
			else
			{
				//LOG_MESSAGE(TME_ERROR, "Output is empty!");
			}
			//////////////////////////////////////////////////////////////////////////
		}
		else
		{
			result = TimeoutErrorMessage;
		}
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


}