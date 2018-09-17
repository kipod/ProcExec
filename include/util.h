#pragma once

namespace PE {
extern LPCWSTR INJECT_DLL;

CStringA Env(LPCSTR varName);
CString PowershellExec(std::vector<CString> scriptLines, DWORD dwTimeout=INFINITE);
CStringA pathToInputFile();
CStringA pathToOutputFile();
CStringA pathToTidFile();
CString pathToInjectDll();
bool GetProcessByExeName(DWORD* Pid, LPCWSTR ExeName = L"EXPLORER.EXE");
}
