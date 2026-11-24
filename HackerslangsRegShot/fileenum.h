#ifndef REGSHOT_FILEENUM_H
#define REGSHOT_FILEENUM_H

#include <windows.h>
#include <tchar.h>

HANDLE FindFirstSnapshotFile(LPCTSTR pattern, WIN32_FIND_DATA* data);

#endif
