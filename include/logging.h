#pragma once
#include <atlstr.h>
#include <atltime.h>

//2018-09-13 17:11:04,398 
//%Y-%m-%d %H:%M:%S,

#define LOGA(format, ...) { CStringA str; CFileTime ft = CFileTime::GetCurrentTime(); CTime t(ft); str.Format("%S,%03d " format "\n", t.Format(L"%Y-%m-%d %H:%M:%S"), ft.GetTime()/10000 % 1000, __VA_ARGS__); ::OutputDebugStringA(str); }
#define LOG(format, ...) { CStringW str; CFileTime ft = CFileTime::GetCurrentTime(); CTime t(ft); str.Format(L"%s,%03d " format L"\n", t.Format(L"%Y-%m-%d %H:%M:%S"), ft.GetTime()/10000 % 1000, __VA_ARGS__); ::OutputDebugStringW(str); }