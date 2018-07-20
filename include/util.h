#pragma once

namespace PE {
CStringA Env(LPCSTR varName);
CString PowershellExec(CString scriptLines, DWORD dwTimeout);
CStringA pathToInputFile();
CStringA pathToOutputFile();

}
