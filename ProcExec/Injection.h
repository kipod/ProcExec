#pragma once

int InjectInProc(HANDLE hProc, HMODULE &hLibModule, DWORD& tid);
BOOL UnloadInjectedModule(HANDLE hProc, HMODULE hModule);
HMODULE GetModuleByName(HANDLE hProc, LPCWSTR moduleName);
