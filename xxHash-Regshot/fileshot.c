/*
    Copyright 2011-2018 Regshot Team
    Copyright 1999-2003,2007,2011 TiANWEi
    Copyright 2004 tulipfan
    Copyright 2026 Hackerslang

    This file is part of Regshot.

    Regshot is free software: you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation, either version 2.1 of the License, or
    (at your option) any later version.

    Regshot is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with Regshot.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "common.h"
#include "checksum.h"
#include "fileenum.h"
#include "usnsnapshot.h"
#include <stdint.h>

// Workaround for older Platform/Windows SDKs (e.g. VS 6.0)
#ifndef INVALID_FILE_ATTRIBUTES
#define INVALID_FILE_ATTRIBUTES ((DWORD)-1)
#endif

// ISDIR, ISFILE added in 1.8.0
#define ISDIR(x)  ( (x&FILE_ATTRIBUTE_DIRECTORY) != 0 )
#define ISFILE(x) ( (x&FILE_ATTRIBUTE_DIRECTORY) == 0 )

SAVEFILECONTENT sFC;
SAVEHEADFILE sHF;

WIN32_FIND_DATA FindData;

//-------------------------------------------------------------
// Get whole file name from FILECONTENT
//-------------------------------------------------------------
LPTSTR GetWholeFileName(LPFILECONTENT lpStartFC, size_t cchExtra)
{
    LPFILECONTENT lpFC;
    LPTSTR lpszName;
    LPTSTR lpszTail;
    size_t cchName;

    cchName = 0;
    for (lpFC = lpStartFC; NULL != lpFC; lpFC = lpFC->lpFatherFC) {
        if (NULL != lpFC->lpszFileName) {
            if (lpFC->cchFileName >= SIZE_MAX / sizeof(TCHAR) - cchName)
                return NULL;
            cchName += lpFC->cchFileName + 1;  // +1 char for backslash or NULL char
        }
    }
    if (0 == cchName) {  // at least create an empty string with NULL char
        cchName++;
    }

    if (cchExtra > SIZE_MAX / sizeof(TCHAR) - cchName)
        return NULL;
    lpszName = MYALLOC0((cchName + cchExtra) * sizeof(TCHAR));
    if (lpszName == NULL)
        return NULL;

    lpszTail = &lpszName[cchName - 1];
    for (lpFC = lpStartFC; NULL != lpFC; lpFC = lpFC->lpFatherFC) {
        if (NULL != lpFC->lpszFileName) {
            cchName = lpFC->cchFileName;
            lpszTail -= cchName;
            memcpy(lpszTail, lpFC->lpszFileName, cchName * sizeof(TCHAR));
            if (lpszTail > lpszName) {
                *--lpszTail = (TCHAR)'\\';
            }
        }
    }
    return lpszName;
}

//--------------------------------------------------
// Walkthrough lpHF chain and find lpszName matches
//--------------------------------------------------
LPHEADFILE SearchDirChain(LPTSTR lpszName, LPHEADFILE lpHF)
{
    if (NULL != lpszName) {
        for (; NULL != lpHF; lpHF = lpHF->lpBrotherHF) {
            if ((NULL != lpHF->lpFirstFC)
                && (NULL != lpHF->lpFirstFC->lpszFileName)
                && (0 == _tcsicmp(lpszName, lpHF->lpFirstFC->lpszFileName))) {
                return lpHF;
            }
        }
    }
    return NULL;
}


// ----------------------------------------------------------------------
// Free all files
// ----------------------------------------------------------------------
VOID FreeAllFileContents(LPFILECONTENT lpFC)
{
    LPFILECONTENT lpBrotherFC;

    for (; NULL != lpFC; lpFC = lpBrotherFC) {
        // Save pointer in local variable
        lpBrotherFC = lpFC->lpBrotherFC;

        // Increase count
        cCurrent++;

        // Free file name
        if (NULL != lpFC->lpszFileName) {
            MYFREE(lpFC->lpszFileName);
        }

        // Update progress bar display
        if (0 != cEnd) {
            nCurrentTime = GetTickCount();
            if (REFRESHINTERVAL < (nCurrentTime - nLastTime)) {
                UI_UpdateProgressBar();
            }
        }

        // If the entry has childs, then do a recursive call for the first child
        if (NULL != lpFC->lpFirstSubFC) {
            FreeAllFileContents(lpFC->lpFirstSubFC);
        }

        // Free entry itself
        MYFREE(lpFC);
    }
}


// ----------------------------------------------------------------------
// Free all head files
// ----------------------------------------------------------------------
VOID FreeAllHeadFiles(LPHEADFILE lpHF)
{
    LPHEADFILE lpBrotherHF;

    for (; NULL != lpHF; lpHF = lpBrotherHF) {
        // Save pointer in local variable
        lpBrotherHF = lpHF->lpBrotherHF;

        // If the entry has childs, then do a recursive call for the first child
        if (NULL != lpHF->lpFirstFC) {
            FreeAllFileContents(lpHF->lpFirstFC);
        }

        // Free entry itself
        MYFREE(lpHF);
    }
}


//-------------------------------------------------------------
// File comparison engine
//-------------------------------------------------------------
static NAMEINDEXENTRY* IndexFiles(LPFILECONTENT first, size_t* count, BOOL unmatchedOnly)
{
    LPFILECONTENT file;
    NAMEINDEXENTRY* entries;
    size_t i = 0;

    *count = 0;
    for (file = first; file != NULL; file = file->lpBrotherFC)
        ++*count;
    entries = AllocateNameIndex(*count);
    if (entries != NULL) {
        for (file = first; file != NULL; file = file->lpBrotherFC, ++i) {
            entries[i].name = file->lpszFileName;
            entries[i].type = ISFILE(file->nFileAttributes);
            entries[i].content = file;
            entries[i].match = unmatchedOnly ? &file->fFileMatch : NULL;
            entries[i].order = i;
        }
        SortNameIndex(entries, *count);
    }
    return entries;
}

static BOOL SameFileMetadata(const FILECONTENT* before, const FILECONTENT* after)
{
    return before->nWriteDateTimeLow == after->nWriteDateTimeLow
        && before->nWriteDateTimeHigh == after->nWriteDateTimeHigh
        && before->nFileSizeLow == after->nFileSizeLow
        && before->nFileSizeHigh == after->nFileSizeHigh
        && before->nFileAttributes == after->nFileAttributes;
}

VOID CompareFiles(LPFILECONTENT lpStartFC1, LPFILECONTENT lpStartFC2)
{
    LPFILECONTENT lpFC1;
    LPFILECONTENT lpFC2;
    size_t fileCount = 0;
    NAMEINDEXENTRY* fileIndex = lpStartFC1 != NULL ? IndexFiles(lpStartFC2, &fileCount, TRUE) : NULL;

    // Compare dirs/files
    for (lpFC1 = lpStartFC1; NULL != lpFC1; lpFC1 = lpFC1->lpBrotherFC) {
        if (ISFILE(lpFC1->nFileAttributes)) {
            CompareResult.stcCompared.cFiles++;
        }
        else {
            CompareResult.stcCompared.cDirs++;
        }
        // Find a matching dir/file for FC1
        for (lpFC2 = fileIndex != NULL
            ? FindNameIndex(fileIndex, fileCount, lpFC1->lpszFileName, ISFILE(lpFC1->nFileAttributes)) : lpStartFC2;
            NULL != lpFC2; lpFC2 = fileIndex != NULL ? NULL : lpFC2->lpBrotherFC) {
            // skip FC2 if already matched
            if (NOMATCH != lpFC2->fFileMatch) {
                continue;
            }
            // skip FC2 if types do *not* match (even if same name then interpret as deleted+added)
            if (ISFILE(lpFC1->nFileAttributes) != ISFILE(lpFC2->nFileAttributes)) {
                continue;
            }
            // skip FC2 if names do *not* match
            if ((NULL == lpFC1->lpszFileName) || (NULL == lpFC2->lpszFileName) || (0 != _tcsicmp(lpFC1->lpszFileName, lpFC2->lpszFileName))) { // 1.8.2 from lstrcmp to strcmp  // 1.9.0 to _tcsicmp
                continue;
            }

            // Same file type and (case-insensitive) name of FC1 found in FC2, so compare their attributes and if applicable their dates and sizes
            if (ISFILE(lpFC1->nFileAttributes)) {
                // Both are files
                if (SameFileMetadata(lpFC1, lpFC2)
                    && (lpFC1->nChkSumUnknown || lpFC2->nChkSumUnknown || lpFC1->nChkSum == lpFC2->nChkSum)) {
                    if (lpFC1->nChkSumUnknown && !lpFC2->nChkSumUnknown) {
                        lpFC2->fFileMatch = WASUNKNOWNBEFORE;
                    } else if (!lpFC1->nChkSumUnknown && lpFC2->nChkSumUnknown) {
                        lpFC2->fFileMatch = ISUNKNOWNAFTER;
                    }
                    else {
                        lpFC2->fFileMatch = ISMATCH;
                    }
                }
                else {
                    // File data differ, so file is modified
                    lpFC2->fFileMatch = ISMODI;
                    CompareResult.stcChanged.cFiles++;
                    CompareResult.stcModified.cFiles++;
                    CreateNewResult(FILEMODI, lpFC1, lpFC2);
                }
            }
            else {
                // Both are dirs
                if (lpFC1->nFileAttributes == lpFC2->nFileAttributes) {
                    // Same dir of FC1 found in FC2
                    lpFC2->fFileMatch = ISMATCH;
                }
                else {
                    // Dir data differ, so dir is modified
                    lpFC2->fFileMatch = ISMODI;
                    CompareResult.stcChanged.cDirs++;
                    CompareResult.stcModified.cDirs++;
                    CreateNewResult(DIRMODI, lpFC1, lpFC2);
                }

                // Compare sub files if any
                if (lpFC1->nScanError == 0 && lpFC2->nScanError == 0
                    && ((NULL != lpFC1->lpFirstSubFC) || (NULL != lpFC2->lpFirstSubFC))) {
                    CompareFiles(lpFC1->lpFirstSubFC, lpFC2->lpFirstSubFC);
                }
            }
            break;
        }
        if (NULL == lpFC2) {
            // FC1 has no matching FC2, so FC1 is a deleted dir/file
            if (ISFILE(lpFC1->nFileAttributes)) {
                CompareResult.stcChanged.cFiles++;
                CompareResult.stcDeleted.cFiles++;
                CreateNewResult(FILEDEL, lpFC1, NULL);
            }
            else {
                CompareResult.stcChanged.cDirs++;
                CompareResult.stcDeleted.cDirs++;
                CreateNewResult(DIRDEL, lpFC1, NULL);
                    
                // "Compare"/Log sub files if any
                if (NULL != lpFC1->lpFirstSubFC) {
                    CompareFiles(lpFC1->lpFirstSubFC, NULL);
                }
            }
        }
    }
    // After looping all FC1 files, do an extra loop over all FC2 files and check previously set match flags to determine added dirs/files
    for (lpFC2 = lpStartFC2; NULL != lpFC2; lpFC2 = lpFC2->lpBrotherFC) {
        // skip FC2 if already matched
        if (NOMATCH != lpFC2->fFileMatch) {
            continue;
        }

        // FC2 has no matching FC1, so FC2 is an added dir/file
        if (ISFILE(lpFC2->nFileAttributes)) {
            CompareResult.stcCompared.cFiles++;
            CompareResult.stcChanged.cFiles++;
            CompareResult.stcAdded.cFiles++;
            CreateNewResult(FILEADD, NULL, lpFC2);
        }
        else {
            CompareResult.stcCompared.cDirs++;
            CompareResult.stcChanged.cDirs++;
            CompareResult.stcAdded.cDirs++;
            CreateNewResult(DIRADD, NULL, lpFC2);

            // "Compare"/Log sub files if any
            if (NULL != lpFC2->lpFirstSubFC) {
                CompareFiles(NULL, lpFC2->lpFirstSubFC);
            }
        }
    }
    if (fileIndex != NULL)
        MYFREE(fileIndex);

    // Update counters display
    nCurrentTime = GetTickCount();
    if (REFRESHINTERVAL < (nCurrentTime - nLastTime)) {
        UI_UpdateCounters(asLangTexts[iszTextDir].lpszText, asLangTexts[iszTextFile].lpszText, CompareResult.stcCompared.cDirs, CompareResult.stcCompared.cFiles);
    }
}

//-------------------------------------------------------------
// Directory and file comparison engine
//-------------------------------------------------------------
VOID CompareHeadFiles(LPHEADFILE lpStartHF1, LPHEADFILE lpStartHF2)
{
    LPHEADFILE lpHF1;
    LPHEADFILE lpHF2;
    LPFILECONTENT lpFC;

    // first loop
    for (lpHF1 = lpStartHF1; NULL != lpHF1; lpHF1 = lpHF1->lpBrotherHF) {
        // Check that first file name present
        if (NULL == lpHF1->lpFirstFC) {
            continue;
        }
        if (NULL == lpHF1->lpFirstFC->lpszFileName) {
            continue;
        }

        // Get corresponding headfile in second shot
        lpHF2 = SearchDirChain(lpHF1->lpFirstFC->lpszFileName, lpStartHF2);
        lpFC = NULL;
        if (NULL != lpHF2) {
            lpHF2->fHeadFileMatch = ISMATCH;
            lpFC = lpHF2->lpFirstFC;
        }
        CompareFiles(lpHF1->lpFirstFC, lpFC);
    }

    // second loop, only those that did not match before
    for (lpHF2 = lpStartHF2; NULL != lpHF2; lpHF2 = lpHF2->lpBrotherHF) {
        // Check that not compared in first loop
        if (NOMATCH != lpHF2->fHeadFileMatch) {
            continue;
        }
        // Check that first file name present
        if (NULL == lpHF2->lpFirstFC) {
            continue;
        }
        if (NULL == lpHF2->lpFirstFC->lpszFileName) {
            continue;
        }

        // Check that there's no corresponding headfile in first shot
        lpHF1 = SearchDirChain(lpHF2->lpFirstFC->lpszFileName, lpStartHF1);
        if (NULL == lpHF1) {
            CompareFiles(NULL, lpHF2->lpFirstFC);
        }
    }
}


// ----------------------------------------------------------------------
// Get file snap shot
// ----------------------------------------------------------------------
static BOOL DirectoryUnavailable(DWORD error)
{
    return error == ERROR_ACCESS_DENIED || error == ERROR_SHARING_VIOLATION
        || error == ERROR_PATH_NOT_FOUND || error == ERROR_FILENAME_EXCED_RANGE
        || error == ERROR_CANT_ACCESS_FILE;
}

static VOID MarkDirectorySkipped(LPREGSHOT lpShot, LPFILECONTENT lpFC, DWORD error)
{
    LPTSTR path = GetWholeFileName(lpFC, 0);
    TCHAR message[128];

    lpFC->nScanError = error;
    lpShot->cSkippedDirs++;
    _sntprintf_s(message, _countof(message), _TRUNCATE,
        TEXT("File snapshot: directory contents skipped (error %lu): "), error);
    OutputDebugString(message);
    if (path != NULL) {
        OutputDebugString(path);
        MYFREE(path);
    }
    OutputDebugString(TEXT("\n"));
}

static BOOL NeedsSnapshotHash(LPREGSHOT shot, LPFILECONTENT before, LPFILECONTENT after,
    BOOL comparisonOnly)
{
    return !shot->fMetadataOnly && (!comparisonOnly
        || (before != NULL && ISFILE(before->nFileAttributes)
            && !before->nChkSumUnknown && SameFileMetadata(before, after)));
}

static VOID HashSnapshotFile(LPREGSHOT shot, LPCTSTR path, LPFILECONTENT file)
{
    CHECKSUM_RESULT result = shot->fTextOnly ? ChecksumTextFile(path, &file->nChkSum)
        : (ChecksumFromFile(path, &file->nChkSum) ? CHECKSUM_OK : CHECKSUM_ERROR);

    file->nChkSumUnknown = result != CHECKSUM_OK;
    if (result == CHECKSUM_ERROR) {
        OutputDebugString(TEXT("Could not hash file: "));
        OutputDebugString(path);
        OutputDebugString(TEXT("\n"));
    }
}

static LPFILECONTENT FindSnapshotEntry(LPFILECONTENT first, NAMEINDEXENTRY* index,
    size_t count, LPCTSTR name, DWORD attributes)
{
    if (index != NULL)
        return FindNameIndex(index, count, name, ISFILE(attributes));
    for (; first != NULL; first = first->lpBrotherFC) {
        if (ISFILE(first->nFileAttributes) == ISFILE(attributes)
            && first->lpszFileName != NULL && _tcsicmp(first->lpszFileName, name) == 0)
            return first;
    }
    return NULL;
}

// lpBaseline is the corresponding node in the first shot, not a live-file hash cache.
static VOID GetFilesSnapAgainst(LPREGSHOT lpShot, LPTSTR lpszFullName, LPFILECONTENT lpFatherFC,
    LPFILECONTENT* lplpCaller, const SNAPSHOT_DIR* lpParentDir,
    LPFILECONTENT lpBaseline, BOOL fComparisonOnly)
{
    LPFILECONTENT lpFC;
    HANDLE hFile;
    SNAPSHOT_DIR sDir;
    BOOL fFound;
    ULONGLONG nFileId;
    DWORD nUsnVolume;
    DWORD cFilesBefore, cDirsBefore, cSkippedBefore;
    LPTSTR lpszEntryPath;
    size_t cchEntryPrefix;
    LPFILECONTENT lpBaselineChildren = NULL;
    NAMEINDEXENTRY* baselineIndex = NULL;
    size_t baselineCount = 0;

    // Full dir/file name is already given

    // Extra local block to reduce stack usage due to recursive calls
    {
        LPTSTR lpszFindFileName;

        lpszFindFileName = NULL;

        // Get father file data if not already provided (=called from FileShot)
        if (NULL == lpFatherFC) {
            // Check if file is to be generic excluded
            if ((NULL == lpszFullName)
                || (((TCHAR)'.' == lpszFullName[0])  // fast exclusion for 99% of the cases
                    && ((0 == _tcscmp(lpszFullName, TEXT(".")))
                        || (0 == _tcscmp(lpszFullName, TEXT("..")))))) {
                return;
            }

            // Create new file content
            lpFatherFC = MYALLOC0(sizeof(FILECONTENT));

            // Set file name length
            lpFatherFC->cchFileName = _tcslen(lpszFullName);

            // Copy file name to new buffer for directory search and more
            lpszFindFileName = MYALLOC0((lpFatherFC->cchFileName + 4 + 1) * sizeof(TCHAR));  // +4 for "\*.*" search when directory (later in routine)
            _tcscpy_s(lpszFindFileName, (lpFatherFC->cchFileName + 4 + 1), lpszFullName);
            // Special case if root dir of a drive was specified, needs trailing backslash otherwise current dir of that drive is used
            if ((TCHAR)':' == lpszFindFileName[lpFatherFC->cchFileName - 1]) {
                lpszFindFileName[lpFatherFC->cchFileName] = (TCHAR)'\\';
                lpszFindFileName[lpFatherFC->cchFileName + 1] = (TCHAR)'\0';
            }

            // Check if file is to be excluded
            if (NULL != lprgszFileSkipStrings[0]) {  // only if there is something to exclude
                if (IsInSkipList(lpszFullName, lprgszFileSkipStrings)) {
                    FreeAllFileContents(lpFatherFC);
                    if (NULL != lpszFindFileName) {
                        MYFREE(lpszFindFileName);
                    }
                    return;
                }
            }

            hFile = FindFirstFile(lpszFindFileName, &FindData);
            if (INVALID_HANDLE_VALUE != hFile) {
                FindClose(hFile);
            }
            else {
                // Workaround for some cases in Windows Vista and later
#ifdef _DEBUG
                DWORD nError;
                LPTSTR lpszMessage;

                nError = GetLastError();
                FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
                    NULL, nError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&lpszMessage, 0, NULL);
                LocalFree(lpszMessage);
#endif

                SecureZeroMemory(&FindData, sizeof(FindData));

                hFile = CreateFile(lpszFindFileName, FILE_READ_ATTRIBUTES,
                    FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                    NULL, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, NULL);
                if (INVALID_HANDLE_VALUE != hFile) {
                    BY_HANDLE_FILE_INFORMATION FileInformation;
                    BOOL bResult;

                    bResult = GetFileInformationByHandle(hFile, &FileInformation);
                    if (bResult) {
                        FindData.dwFileAttributes = FileInformation.dwFileAttributes;
                        FindData.ftCreationTime = FileInformation.ftCreationTime;
                        FindData.ftLastAccessTime = FileInformation.ftLastAccessTime;
                        FindData.ftLastWriteTime = FileInformation.ftLastWriteTime;
                        FindData.nFileSizeHigh = FileInformation.nFileSizeHigh;
                        FindData.nFileSizeLow = FileInformation.nFileSizeLow;
                    }
                    else {
                        FindData.dwFileAttributes = GetFileAttributes(lpszFullName);
                        if (INVALID_FILE_ATTRIBUTES == FindData.dwFileAttributes) {
                            FindData.dwFileAttributes = 0;
                        }
                        bResult = GetFileTime(hFile, &FindData.ftCreationTime, &FindData.ftLastAccessTime, &FindData.ftLastWriteTime);
                        if (!bResult) {
                            FindData.ftCreationTime.dwLowDateTime = 0;
                            FindData.ftCreationTime.dwHighDateTime = 0;
                            FindData.ftLastAccessTime.dwLowDateTime = 0;
                            FindData.ftLastAccessTime.dwHighDateTime = 0;
                            FindData.ftLastWriteTime.dwLowDateTime = 0;
                            FindData.ftLastWriteTime.dwHighDateTime = 0;
                        }
                        FindData.nFileSizeLow = GetFileSize(hFile, &FindData.nFileSizeHigh);
                        if (INVALID_FILE_SIZE == FindData.nFileSizeLow) {
                            FindData.nFileSizeHigh = 0;
                            FindData.nFileSizeLow = 0;
                        }
                    }
                    CloseHandle(hFile);
                }
                else {
                    lpShot->fIncomplete = TRUE;
                    OutputDebugString(TEXT("File snapshot: root path could not be read.\n"));
                    FreeAllFileContents(lpFatherFC);
                    MYFREE(lpszFindFileName);
                    return;
                }
            }

            // Remove previously added backslash (if any)
            lpszFindFileName[lpFatherFC->cchFileName] = (TCHAR)'\0';

            // Copy pointer to current file into caller's pointer
            if (NULL != lplpCaller) {
                *lplpCaller = lpFatherFC;
            }

            // Increase dir/file count
            if (ISFILE(FindData.dwFileAttributes)) {
                lpShot->stCounts.cFiles++;
            }
            else {
                lpShot->stCounts.cDirs++;
            }

            // Copy file name
            lpFatherFC->lpszFileName = MYALLOC0((lpFatherFC->cchFileName + 1) * sizeof(TCHAR));
            _tcscpy_s(lpFatherFC->lpszFileName, lpFatherFC->cchFileName + 1, lpszFullName);

            // Copy file data
            lpFatherFC->nWriteDateTimeLow = FindData.ftLastWriteTime.dwLowDateTime;
            lpFatherFC->nWriteDateTimeHigh = FindData.ftLastWriteTime.dwHighDateTime;
            lpFatherFC->nFileSizeLow = FindData.nFileSizeLow;
            lpFatherFC->nFileSizeHigh = FindData.nFileSizeHigh;
            lpFatherFC->nFileAttributes = FindData.dwFileAttributes;
            lpFatherFC->nChkSumUnknown = TRUE;
            if (ISFILE(lpFatherFC->nFileAttributes)
                && NeedsSnapshotHash(lpShot, lpBaseline, lpFatherFC, fComparisonOnly)) {
                HashSnapshotFile(lpShot, lpszFullName, lpFatherFC);
            }

            // Set "lpFirstSubFC" pointer for storing the first child's pointer
            lplpCaller = &lpFatherFC->lpFirstSubFC;
        }

        // If father is a file, then leave (=special case when called from FileShot)
        if (ISFILE(lpFatherFC->nFileAttributes)) {
            if (NULL != lpszFindFileName) {
                MYFREE(lpszFindFileName);
            }
            return;
        }

        // Process all entries of directory
        // a) Create search pattern and start search
        if (NULL == lpszFindFileName 
            || _tcslen(lpszFindFileName) == 0
            || lpszFindFileName[0] == (TCHAR)'\0'
            || 0 == _tcscmp(lpszFindFileName, TEXT(""))) {
            lpszFindFileName = lpszFullName;
        }

        _tcscat_s(lpszFindFileName, _tcslen(lpszFindFileName) + 4 + 1, TEXT("\\*.*"));
        fFound = SnapshotDirOpen(&sDir, lpszFindFileName,
            NULL != lpShot->lpUsnSnapshot && (lpParentDir == NULL || !lpParentDir->skipIds), lpParentDir,
            (NULL != lpFatherFC) ? lpFatherFC->nFileId : 0, &FindData, &nFileId);
        nUsnVolume = 0;
        if (fFound && sDir.ids) {
            nUsnVolume = UsnSnapshotVolume(lpShot->lpUsnSnapshot, sDir.volumeGuid, sDir.volumeSerial);
            if (nUsnVolume == 0)
                fFound = SnapshotDirRestartClassic(&sDir, lpszFindFileName, &FindData, &nFileId);
        }
        if (lpszFindFileName != lpszFullName) {
            MYFREE(lpszFindFileName);
        }
    }  // End of extra local block
    if (!fFound) {  // error: nothing in dir, no access, etc.
        DWORD error = GetLastError();

        if (DirectoryUnavailable(error)) {
            MarkDirectorySkipped(lpShot, lpFatherFC, error);
        }
        else if (error != ERROR_NO_MORE_FILES && error != ERROR_FILE_NOT_FOUND) {
            lpShot->fIncomplete = TRUE;
            OutputDebugString(TEXT("File snapshot: could not enumerate directory.\n"));
        }
#ifdef _DEBUG
        DWORD nError;
        LPTSTR lpszMessage;

        nError = GetLastError();
        FormatMessage(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
            NULL, nError, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPTSTR)&lpszMessage, 0, NULL);
        LocalFree(lpszMessage);
#endif
        return;
    }
    lpszEntryPath = GetWholeFileName(lpFatherFC, MAX_PATH + 5);
    if (lpszEntryPath == NULL) {
        SnapshotDirClose(&sDir);
        lpShot->fIncomplete = TRUE;
        OutputDebugString(TEXT("File snapshot: not enough memory for directory entry paths.\n"));
        return;
    }
    cchEntryPrefix = _tcslen(lpszEntryPath);
    lpszEntryPath[cchEntryPrefix++] = (TCHAR)'\\';
    if (fComparisonOnly && !lpShot->fMetadataOnly && lpBaseline != NULL
        && ISDIR(lpBaseline->nFileAttributes) && lpBaseline->nScanError == 0) {
        lpBaselineChildren = lpBaseline->lpFirstSubFC;
        baselineIndex = IndexFiles(lpBaselineChildren, &baselineCount, FALSE);
    }
    cFilesBefore = lpShot->stCounts.cFiles;
    cDirsBefore = lpShot->stCounts.cDirs;
    cSkippedBefore = lpShot->cSkippedDirs;
    // b) process entry then find next
    do {
        LPFILECONTENT lpBefore;
        BOOL fNeedHash;

        // Check if file is to be generic excluded
        if ((NULL == FindData.cFileName)
            || (((TCHAR)'.' == FindData.cFileName[0])  // fast exclusion for 99% of the cases
                && ((0 == _tcscmp(FindData.cFileName, TEXT(".")))
                    || (0 == _tcscmp(FindData.cFileName, TEXT("..")))))) {
            continue;  // ignore this entry and continue with next file
        }

        // Check if dir/file is to be excluded
        if (NULL != lprgszFileSkipStrings[0]) {  // only if there is something to exclude
            if (IsInSkipList(FindData.cFileName, lprgszFileSkipStrings)) {
                continue;  // ignore this entry and continue with next file
            }
        }
        _tcscpy_s(lpszEntryPath + cchEntryPrefix, MAX_PATH + 4, FindData.cFileName);
        if (NULL != lprgszFileSkipStrings[0]) {
            if (IsInSkipList(lpszEntryPath, lprgszFileSkipStrings)) {
                continue;  // ignore this entry and continue with next file
            }
        }

        lpFC = MYALLOC0(sizeof(FILECONTENT));
        lpFC->lpFatherFC = lpFatherFC;
        lpFC->cchFileName = _tcslen(FindData.cFileName);

        // Copy pointer to current file into caller's pointer
        if (NULL != lplpCaller) {
            *lplpCaller = lpFC;
        }

        // Increase dir/file count
        if (ISFILE(FindData.dwFileAttributes)) {
            lpShot->stCounts.cFiles++;
        }
        else {
            lpShot->stCounts.cDirs++;
        }

        // Copy file name
        lpFC->lpszFileName = MYALLOC0((lpFC->cchFileName + 1) * sizeof(TCHAR));
        _tcscpy_s(lpFC->lpszFileName, lpFC->cchFileName + 1, FindData.cFileName);

        // Copy file data
        lpFC->nWriteDateTimeLow = FindData.ftLastWriteTime.dwLowDateTime;
        lpFC->nWriteDateTimeHigh = FindData.ftLastWriteTime.dwHighDateTime;
        lpFC->nFileSizeLow = FindData.nFileSizeLow;
        lpFC->nFileSizeHigh = FindData.nFileSizeHigh;
        lpFC->nFileAttributes = FindData.dwFileAttributes;
        lpFC->nChkSumUnknown = TRUE;
        lpBefore = FindSnapshotEntry(lpBaselineChildren, baselineIndex, baselineCount,
            FindData.cFileName, FindData.dwFileAttributes);
        fNeedHash = NeedsSnapshotHash(lpShot, lpBefore, lpFC, fComparisonOnly);
        if (ISFILE(FindData.dwFileAttributes)) {
            BOOL fCacheable = FALSE;

            if ((0 != nUsnVolume) && (0 != nFileId)) {
                ULONGLONG nSize = ((ULONGLONG)FindData.nFileSizeHigh << 32) | FindData.nFileSizeLow;
                ULONGLONG nWriteTime = ((ULONGLONG)FindData.ftLastWriteTime.dwHighDateTime << 32) | FindData.ftLastWriteTime.dwLowDateTime;

                lpFC->nFileId = nFileId;
                lpFC->nUsnVolume = nUsnVolume;
                if (fNeedHash) {
                    fCacheable = UsnSnapshotCanCache(lpShot->lpUsnSnapshot, nUsnVolume, nFileId, FindData.dwFileAttributes);
                    if ((!lpShot->fTextOnly || IsKnownTextExtension(lpszEntryPath))
                        && UsnSnapshotReuseHash(lpShot->lpUsnSnapshot, nUsnVolume, nFileId, nSize, nWriteTime, FindData.dwFileAttributes, &lpFC->nChkSum)) {
                        lpFC->nChkSumUnknown = FALSE;
                        lpFC->fUsnFlags |= USNFC_REUSED;
                    }
                }
            }
            if (fNeedHash && !(lpFC->fUsnFlags & USNFC_REUSED)) {
                HashSnapshotFile(lpShot, lpszEntryPath, lpFC);
            }
            if (fCacheable && !lpFC->nChkSumUnknown) {
                lpFC->fUsnFlags |= USNFC_CACHEABLE;
            }
        }
        else {
            lpFC->nChkSumUnknown = TRUE;
        }

        // Update counters display
        nCurrentTime = GetTickCount();
        if (REFRESHINTERVAL < (nCurrentTime - nLastTime)) {
            UI_UpdateCounters(asLangTexts[iszTextDir].lpszText, asLangTexts[iszTextFile].lpszText, lpShot->stCounts.cDirs, lpShot->stCounts.cFiles);
        }

        // ATTENTION!!! FindData will be INVALID from this point on, due to recursive calls
        // If the entry is a directory, then do a recursive call for it
        // Pass this entry as father and "lpFirstSubFC" pointer for storing the first child's pointer
        if (ISDIR(lpFC->nFileAttributes)) {
            lpFC->nFileId = nFileId;
            if (lpFC->nFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) {
                MarkDirectorySkipped(lpShot, lpFC, ERROR_CANT_ACCESS_FILE);
            }
            else {
                GetFilesSnapAgainst(lpShot, lpszEntryPath, lpFC, &lpFC->lpFirstSubFC, &sDir,
                    lpBefore, fComparisonOnly);
            }
        }

        // Set "lpBrotherFC" pointer for storing the next brother's pointer
        lplpCaller = &lpFC->lpBrotherFC;
    } while (SnapshotDirNext(&sDir, &FindData, &nFileId));
    {
        DWORD error = GetLastError();
        BOOL retry = sDir.ids && error != ERROR_NO_MORE_FILES;

        if (baselineIndex != NULL)
            MYFREE(baselineIndex);
        MYFREE(lpszEntryPath);
        SnapshotDirClose(&sDir);
        if (retry) {
            SNAPSHOT_DIR classicParent;
            LPTSTR path = GetWholeFileName(lpFatherFC, 4);

            ZeroMemory(&classicParent, sizeof(classicParent));
            classicParent.skipIds = TRUE;
            FreeAllFileContents(lpFatherFC->lpFirstSubFC);
            lpFatherFC->lpFirstSubFC = NULL;
            lpShot->stCounts.cFiles = cFilesBefore;
            lpShot->stCounts.cDirs = cDirsBefore;
            lpShot->cSkippedDirs = cSkippedBefore;
            if (path == NULL) {
                lpShot->fIncomplete = TRUE;
                OutputDebugString(TEXT("File snapshot: not enough memory to restart directory enumeration.\n"));
                return;
            }
            OutputDebugString(TEXT("File snapshot: ID enumeration failed; restarting directory with classic enumeration.\n"));
            GetFilesSnapAgainst(lpShot, path, lpFatherFC, &lpFatherFC->lpFirstSubFC, &classicParent,
                lpBaseline, fComparisonOnly);
            MYFREE(path);
        }
        else if (DirectoryUnavailable(error)) {
            FreeAllFileContents(lpFatherFC->lpFirstSubFC);
            lpFatherFC->lpFirstSubFC = NULL;
            lpShot->stCounts.cFiles = cFilesBefore;
            lpShot->stCounts.cDirs = cDirsBefore;
            lpShot->cSkippedDirs = cSkippedBefore;
            MarkDirectorySkipped(lpShot, lpFatherFC, error);
        }
        else if (error != ERROR_NO_MORE_FILES) {
            lpShot->fIncomplete = TRUE;
            OutputDebugString(TEXT("File snapshot: directory enumeration stopped unexpectedly.\n"));
        }
    }
}

static VOID GetFilesSnap(LPREGSHOT lpShot, LPTSTR lpszFullName, LPFILECONTENT lpFatherFC,
    LPFILECONTENT* lplpCaller, const SNAPSHOT_DIR* lpParentDir)
{
    BOOL comparisonOnly = lpShot == &Shot2 && Shot1.fFilled && !Shot1.fIncomplete;
    LPHEADFILE baseline = comparisonOnly ? SearchDirChain(lpszFullName, Shot1.lpHF) : NULL;

    GetFilesSnapAgainst(lpShot, lpszFullName, lpFatherFC, lplpCaller, lpParentDir,
        baseline != NULL ? baseline->lpFirstFC : NULL, comparisonOnly);
}

// ----------------------------------------------------------------------
// USN incremental mode helpers
// ----------------------------------------------------------------------
#ifdef _WINDOWS
static LPTSTR GetUsnBaselinePath(VOID)
{
    static const TCHAR szBaselineName[] = TEXT("RegshotUsnBaseline.dat");
    LPTSTR lpszPath;
    LPTSTR lpszSlash;
    size_t cchPath;

    if (NULL == lpszRegshotIni) {
        return NULL;
    }
    cchPath = _tcslen(lpszRegshotIni) + _countof(szBaselineName) + 1;
    lpszPath = MYALLOC0(cchPath * sizeof(TCHAR));
    if (NULL == lpszPath) {
        return NULL;
    }
    _tcscpy_s(lpszPath, cchPath, lpszRegshotIni);
    lpszSlash = _tcsrchr(lpszPath, (TCHAR)'\\');
    if (NULL == lpszSlash) {
        lpszPath[0] = (TCHAR)'\0';
    }
    else {
        lpszSlash[1] = (TCHAR)'\0';
    }
    _tcscat_s(lpszPath, cchPath, szBaselineName);
    return lpszPath;
}
#endif

typedef struct {
    USN_SNAPSHOT* lpSnapshot;
    LPREGSHOT lpShot;
    USN_CHANGE_SET* lpLateChanges;
    BYTE* lpLateState;  // per volume: 0 = not read, 1 = read, 2 = failed
} USN_VERIFY_CONTEXT;

// Re-hash reused files changed after the volume checkpoint while the scan ran
static VOID VerifyReusedHashes(USN_VERIFY_CONTEXT* lpContext, LPFILECONTENT lpFC)
{
    for (; NULL != lpFC; lpFC = lpFC->lpBrotherFC) {
        if (lpFC->fUsnFlags & USNFC_REUSED) {
            DWORD nVolume = lpFC->nUsnVolume;
            BOOL fRehash = TRUE;

            if ((NULL != lpContext->lpLateChanges) && (NULL != lpContext->lpLateState)
                && (0 < nVolume) && (USN_BASELINE_MAX_VOLUMES >= nVolume)) {
                if (0 == lpContext->lpLateState[nVolume - 1]) {
                    lpContext->lpLateState[nVolume - 1] = UsnSnapshotReadLateChanges(lpContext->lpSnapshot, nVolume, &lpContext->lpLateChanges[nVolume - 1]) ? 1 : 2;
                }
                fRehash = (1 != lpContext->lpLateState[nVolume - 1])
                    || (0 != UsnChangeSetFlags(&lpContext->lpLateChanges[nVolume - 1], lpFC->nFileId));
            }
            if (fRehash) {
                LPTSTR lpszFullFileName = GetWholeFileName(lpFC, 0);

                lpFC->fUsnFlags &= ~USNFC_REUSED;
                if (lpszFullFileName == NULL) {
                    lpFC->nChkSumUnknown = TRUE;
                    OutputDebugString(TEXT("Could not allocate path for USN hash verification.\n"));
                }
                else {
                    HashSnapshotFile(lpContext->lpShot, lpszFullFileName, lpFC);
                    MYFREE(lpszFullFileName);
                }
                if (lpFC->nChkSumUnknown) {
                    lpFC->fUsnFlags &= ~USNFC_CACHEABLE;
                }
            }
        }
        if (NULL != lpFC->lpFirstSubFC) {
            VerifyReusedHashes(lpContext, lpFC->lpFirstSubFC);
        }
    }
}

static VOID FinishUsnScan(LPREGSHOT lpShot)
{
    USN_VERIFY_CONTEXT sContext;
    LPHEADFILE lpHF;
    DWORD i;

    if (lpShot->fMetadataOnly) {
        UsnSnapshotEndScan(lpShot->lpUsnSnapshot);
        return;
    }
    sContext.lpSnapshot = lpShot->lpUsnSnapshot;
    sContext.lpShot = lpShot;
    sContext.lpLateChanges = MYALLOC0(USN_BASELINE_MAX_VOLUMES * sizeof(USN_CHANGE_SET));
    sContext.lpLateState = MYALLOC0(USN_BASELINE_MAX_VOLUMES * sizeof(BYTE));
    for (lpHF = lpShot->lpHF; NULL != lpHF; lpHF = lpHF->lpBrotherHF) {
        VerifyReusedHashes(&sContext, lpHF->lpFirstFC);
    }
    if (NULL != sContext.lpLateChanges) {
        for (i = 0; i < USN_BASELINE_MAX_VOLUMES; i++) {
            UsnChangeSetFree(&sContext.lpLateChanges[i]);
        }
        MYFREE(sContext.lpLateChanges);
    }
    if (NULL != sContext.lpLateState) {
        MYFREE(sContext.lpLateState);
    }
    UsnSnapshotEndScan(lpShot->lpUsnSnapshot);
}

static DWORD CollectUsnEntries(LPFILECONTENT lpFC, USN_BASELINE_ENTRY* lpEntries, DWORD nCount)
{
    for (; NULL != lpFC; lpFC = lpFC->lpBrotherFC) {
        if ((lpFC->fUsnFlags & USNFC_CACHEABLE) && !lpFC->nChkSumUnknown && (0 != lpFC->nUsnVolume)) {
            if (NULL != lpEntries) {
                USN_BASELINE_ENTRY* lpEntry = &lpEntries[nCount];

                lpEntry->fileId = lpFC->nFileId;
                lpEntry->size = ((ULONGLONG)lpFC->nFileSizeHigh << 32) | lpFC->nFileSizeLow;
                lpEntry->writeTime = ((ULONGLONG)lpFC->nWriteDateTimeHigh << 32) | lpFC->nWriteDateTimeLow;
                lpEntry->hash = lpFC->nChkSum;
                lpEntry->volume = lpFC->nUsnVolume - 1;
                lpEntry->attributes = lpFC->nFileAttributes;
            }
            nCount++;
        }
        if (NULL != lpFC->lpFirstSubFC) {
            nCount = CollectUsnEntries(lpFC->lpFirstSubFC, lpEntries, nCount);
        }
    }
    return nCount;
}

// ----------------------------------------------------------------------
// Replace the USN baseline with the saved shot's data, or remove it
// ----------------------------------------------------------------------
VOID SaveUsnBaseline(LPREGSHOT lpShot, BOOL fHiveSaved)
{
#ifdef _WINDOWS
    LPTSTR lpszPath;
    BOOL fSaved = FALSE;

    lpszPath = GetUsnBaselinePath();
    if (NULL == lpszPath) {
        return;
    }
    if (fHiveSaved && (NULL != lpShot->lpUsnSnapshot)) {
        USN_BASELINE_ENTRY* lpEntries = NULL;
        LPHEADFILE lpHF;
        DWORD nCount = 0;

        for (lpHF = lpShot->lpHF; NULL != lpHF; lpHF = lpHF->lpBrotherHF) {
            nCount = CollectUsnEntries(lpHF->lpFirstFC, NULL, nCount);
        }
        if (0 < nCount) {
            lpEntries = MYALLOC0(nCount * sizeof(USN_BASELINE_ENTRY));
        }
        if ((0 == nCount) || (NULL != lpEntries)) {
            DWORD nFilled = 0;

            for (lpHF = lpShot->lpHF; NULL != lpHF; lpHF = lpHF->lpBrotherHF) {
                nFilled = CollectUsnEntries(lpHF->lpFirstFC, lpEntries, nFilled);
            }
            fSaved = UsnSnapshotSaveBaseline(lpShot->lpUsnSnapshot, lpEntries, nFilled, lpszPath);
        }
        if (NULL != lpEntries) {
            MYFREE(lpEntries);
        }
    }
    if (!fSaved) {
        OutputDebugString(TEXT("USN: baseline unavailable or save failed; removing it.\n"));
        DeleteFile(lpszPath);  // never keep a baseline from an older save
    }
    MYFREE(lpszPath);
#else
    UNREFERENCED_PARAMETER(lpShot);
    UNREFERENCED_PARAMETER(fHiveSaved);
#endif
}

// ----------------------------------------------------------------------
// File Shot Engine
// ----------------------------------------------------------------------
static BOOL TrimSnapshotPath(LPTSTR path)
{
    size_t length = _tcslen(path);

    while (length > 0 && (path[length - 1] == (TCHAR)'\\' || path[length - 1] == (TCHAR)' '))
        path[--length] = 0;
    return length != 0;
}

VOID FileShot(LPREGSHOT lpShot)
{
#ifdef _WINDOWS
    UINT cchExtDir;
    lpShot->fMetadataOnly = BST_CHECKED != SendMessage(GetDlgItem(hWnd, IDC_CHECKHASH), BM_GETCHECK, (WPARAM)0, (LPARAM)0);
    lpShot->fTextOnly = BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_CHECKTEXT), BM_GETCHECK, (WPARAM)0, (LPARAM)0);
    cchExtDir = GetDlgItemText(hWnd, IDC_EDITDIR, lpszExtDir, EXTDIRLEN);  // length incl. NULL character
#endif
#ifdef _CONSOLE
    size_t cchExtDir = 0;
    cchExtDir = _tcslen(lpszExtDir);
#endif

#ifdef _WINDOWS
    if ((0 < cchExtDir) && (1 == SendMessage(GetDlgItem(hWnd, IDC_CHECKUSN), BM_GETCHECK, (WPARAM)0, (LPARAM)0))) {
        LPTSTR lpszBaselinePath = GetUsnBaselinePath();

        lpShot->lpUsnSnapshot = UsnSnapshotBegin(lpszBaselinePath);
        if (NULL != lpszBaselinePath) {
            MYFREE(lpszBaselinePath);
        }
    }
#endif

    if (0 < cchExtDir) {
        LPHEADFILE* lplpHFPrev;
        LPTSTR lpszSubExtDir;
        size_t i;

        lplpHFPrev = &lpShot->lpHF;
        lpszSubExtDir = lpszExtDir;
        for (i = 0; i <= cchExtDir; i++) {
            // Split each directory in string
            if (((TCHAR)';' == lpszExtDir[i]) || ((TCHAR)'\0' == lpszExtDir[i])) {
                LPHEADFILE lpHF;

                lpszExtDir[i] = (TCHAR)'\0';

                // if anything is left then process this directory
                if (TrimSnapshotPath(lpszSubExtDir)) {
                    lpHF = MYALLOC0(sizeof(HEADFILE));

                    *lplpHFPrev = lpHF;
                    lplpHFPrev = &lpHF->lpBrotherHF;

                    GetFilesSnap(lpShot, lpszSubExtDir, NULL, &lpHF->lpFirstFC, NULL);
                }

                lpszSubExtDir = &lpszExtDir[i + 1];
            }
        }
    }

    if (NULL != lpShot->lpUsnSnapshot) {
        FinishUsnScan(lpShot);
    }
}


// ----------------------------------------------------------------------
// Clear comparison match flags of directories and files
// ----------------------------------------------------------------------
VOID ClearFileMatchFlags(LPFILECONTENT lpFC)
{
    for (; NULL != lpFC; lpFC = lpFC->lpBrotherFC) {
        lpFC->fFileMatch = NOMATCH;
        if (NULL != lpFC->lpFirstSubFC) {
            ClearFileMatchFlags(lpFC->lpFirstSubFC);
        }
    }
}

// ----------------------------------------------------------------------
// Clear comparison match flags in all head files
// ----------------------------------------------------------------------
VOID ClearHeadFileMatchFlags(LPHEADFILE lpHF)
{
    for (; NULL != lpHF; lpHF = lpHF->lpBrotherHF) {
        lpHF->fHeadFileMatch = NOMATCH;
        if (NULL != lpHF->lpFirstFC) {
            ClearFileMatchFlags(lpHF->lpFirstFC);
        }
    }
}


// ----------------------------------------------------------------------
// Save file to HIVE File
//
// This routine is called recursively to store the entries of the dir/file tree
// Therefore temporary vars are put in a local block to reduce stack usage
// ----------------------------------------------------------------------
VOID SaveFiles(LPREGSHOT lpShot, LPFILECONTENT lpFC, DWORD nFPFatherFile, DWORD nFPCaller)
{
    DWORD nFPFile;

    for (; NULL != lpFC; lpFC = lpFC->lpBrotherFC) {
        // Get current file position
        // put in a separate var for later use
        nFPFile = fileextradata.ofsFBFile + fileextradata.ofsFBuffer;

        // Write position of current file in caller's field
        if (0 < nFPCaller) {
            WriteFileBuffer(nFPCaller, &nFPFile, sizeof(nFPFile));
        }

        // Initialize file content

        // Copy values
        sFC.nWriteDateTimeLow = lpFC->nWriteDateTimeLow;
        sFC.nWriteDateTimeHigh = lpFC->nWriteDateTimeHigh;
        sFC.nFileSizeLow = lpFC->nFileSizeLow;
        sFC.nFileSizeHigh = lpFC->nFileSizeHigh;
        sFC.nFileAttributes = lpFC->nFileAttributes;
        sFC.nChkSum = 0;
        sFC.nHashLow = (DWORD)lpFC->nChkSum;
        sFC.nHashHigh = (DWORD)(lpFC->nChkSum >> 32);
        sFC.fHashValid = !lpFC->nChkSumUnknown;
        sFC.nScanError = lpFC->nScanError;

        // Set file positions of the relatives inside the tree
#ifdef _UNICODE
        sFC.ofsFileName = 0;      // not known yet, may be defined in this call
#endif
#ifndef _UNICODE
        // File name will always be stored behind the structure, so its position is already known
        sFC.ofsFileName = nFPFile + sizeof(sFC);
#endif
        sFC.ofsFirstSubFile = 0;  // not known yet, may be re-written by another recursive call
        sFC.ofsBrotherFile = 0;   // not known yet, may be re-written in another iteration
        sFC.ofsFatherFile = nFPFatherFile;

        // New since file content version 2
        sFC.nFileNameLen = 0;

        // Determine file name length
        if (NULL != lpFC->lpszFileName) {
            sFC.nFileNameLen = (DWORD)lpFC->cchFileName;
            if (0 < sFC.nFileNameLen) {  // otherwise leave it all 0
                sFC.nFileNameLen++;  // account for NULL char
#ifdef _UNICODE
                // File name will always be stored behind the structure, so its position is already known
                sFC.ofsFileName = nFPFile + sizeof(sFC);
#endif
            }
        }

        // Increase count
        cCurrent++;

        // Write file content to file
        // Make sure that ALL fields have been initialized/set
        WriteFileBuffer(-1, &sFC, sizeof(sFC));

        // Write file name to file
        if (0 < sFC.nFileNameLen) {
            WriteFileBuffer(-1, lpFC->lpszFileName, sFC.nFileNameLen * sizeof(TCHAR));
#ifndef _UNICODE
        }
        else {
            // Write empty string for backward compatibility
            WriteFileBuffer(-1, lpszEmpty, 1 * sizeof(TCHAR));
#endif
        }

        // Update progress bar display
        if (0 != cEnd) {
            nCurrentTime = GetTickCount();
            if (REFRESHINTERVAL < (nCurrentTime - nLastTime)) {
                UI_UpdateProgressBar();
            }
        }

        // ATTENTION!!! sFC is INVALID from this point on, due to recursive calls
        // If the entry has childs, then do a recursive call for the first child
        // Pass this entry as father and "ofsFirstSubFile" position for storing the first child's position
        if (NULL != lpFC->lpFirstSubFC) {
            SaveFiles(lpShot, lpFC->lpFirstSubFC, nFPFile, nFPFile + offsetof(SAVEFILECONTENT, ofsFirstSubFile));
        }

        // Set "ofsBrotherFile" position for storing the following brother's position
        nFPCaller = nFPFile + offsetof(SAVEFILECONTENT, ofsBrotherFile);
    }
}

//--------------------------------------------------
// Save head file to HIVE file
//--------------------------------------------------
VOID SaveHeadFiles(LPREGSHOT lpShot, LPHEADFILE lpHF, DWORD nFPCaller)
{
    DWORD nFPHF;

    // Write all head files and their file contents
    for (; NULL != lpHF; lpHF = lpHF->lpBrotherHF) {
        // Get current file position
        // put in a separate var for later use
        nFPHF = fileextradata.ofsFBFile + fileextradata.ofsFBuffer;

        // Write position of current head file in caller's field
        if (0 < nFPCaller) {
            WriteFileBuffer(nFPCaller, &nFPHF, sizeof(nFPHF));
        }

        // Initialize head file

        // Set file positions of the relatives inside the tree
        sHF.ofsBrotherHeadFile = 0;   // not known yet, may be re-written in next iteration
        sHF.ofsFirstFileContent = 0;  // not known yet, may be re-written by SaveFiles call

        // Write head file to file
        // Make sure that ALL fields have been initialized/set
        WriteFileBuffer(-1, &sHF, sizeof(sHF));

        // Write all file contents of head file
        if (NULL != lpHF->lpFirstFC) {
            SaveFiles(lpShot, lpHF->lpFirstFC, 0, nFPHF + offsetof(SAVEHEADFILE, ofsFirstFileContent));
        }

        // Set "ofsBrotherHeadFile" position for storing the following brother's position
        nFPCaller = nFPHF + offsetof(SAVEHEADFILE, ofsBrotherHeadFile);
    }
}


// ----------------------------------------------------------------------
// Load file from HIVE file
// ----------------------------------------------------------------------
VOID LoadFiles(LPREGSHOT lpShot, DWORD ofsFile, LPFILECONTENT lpFatherFC, LPFILECONTENT* lplpCaller)
{
    LPFILECONTENT lpFC;
    DWORD ofsBrotherFile;

    // Read all files and their sub file contents
    for (; !lpShot->fIncomplete && 0 != ofsFile; ofsFile = ofsBrotherFile) {
        // Copy SAVEFILECONTENT to aligned memory block
        ZeroMemory(&sFC, sizeof(sFC));
        CopyMemory(&sFC, (lpFileBuffer + ofsFile), fileheader.nFCSize);

        // Save offset in local variable
        ofsBrotherFile = sFC.ofsBrotherFile;

        // Create new file content
        // put in a separate var for later use
        lpFC = MYALLOC0(sizeof(FILECONTENT));
        if (lpFC == NULL) {
            lpShot->fIncomplete = TRUE;
            return;
        }

        // Set father of current file
        lpFC->lpFatherFC = lpFatherFC;

        // Copy file name
        if (fileextradata.bOldFCVersion) {  // old SBCS/MBCS version
            sFC.nFileNameLen = (DWORD)strlen((const char*)(lpFileBuffer + sFC.ofsFileName));
            if (0 < sFC.nFileNameLen) {
                sFC.nFileNameLen++;  // account for NULL char
            }
        }
        if (0 < sFC.nFileNameLen) {  // otherwise leave it NULL
            // Copy string to an aligned memory block
            nSourceSize = sFC.nFileNameLen * fileheader.nCharSize;
            nStringBufferSize = AdjustBuffer(&lpStringBuffer, nStringBufferSize, nSourceSize, REGSHOT_BUFFER_BLOCK_BYTES);
            if (lpStringBuffer == NULL) {
                lpShot->fIncomplete = TRUE;
                FreeAllFileContents(lpFC);
                return;
            }
            ZeroMemory(lpStringBuffer, nStringBufferSize);
            CopyMemory(lpStringBuffer, (lpFileBuffer + sFC.ofsFileName), nSourceSize);

            lpFC->lpszFileName = MYALLOC0(sFC.nFileNameLen * sizeof(TCHAR));
            if (lpFC->lpszFileName == NULL) {
                lpShot->fIncomplete = TRUE;
                FreeAllFileContents(lpFC);
                return;
            }
            if (fileextradata.bSameCharSize) {
                _tcsncpy_s(lpFC->lpszFileName, sFC.nFileNameLen, lpStringBuffer, sFC.nFileNameLen);
            }
            else {
#ifdef _UNICODE
                MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, (LPCSTR)lpStringBuffer, -1, lpFC->lpszFileName, sFC.nFileNameLen);
#else
                WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK | WC_DEFAULTCHAR, (LPCWSTR)lpStringBuffer, -1, lpFC->lpszFileName, sFC.nFileNameLen, NULL, NULL);
#endif
            }
            lpFC->lpszFileName[sFC.nFileNameLen - 1] = (TCHAR)'\0';  // safety NULL char

            // Set file name length in chars
            lpFC->cchFileName = _tcslen(lpFC->lpszFileName);
        }

        // Check if file is to be generic excluded
        if ((NULL == lpFC->lpszFileName)
            || (((TCHAR)'.' == lpFC->lpszFileName[0])  // fast exclusion for 99% of the cases
                && ((0 == _tcscmp(lpFC->lpszFileName, TEXT(".")))
                    || (0 == _tcscmp(lpFC->lpszFileName, TEXT("..")))))) {
            FreeAllFileContents(lpFC);
            continue;  // ignore this entry and continue with next brother file
        }

        // Check if file is to be excluded
        if (NULL != lprgszFileSkipStrings[0]) {  // only if there is something to exclude
            LPTSTR lpszFullName;

            if (IsInSkipList(lpFC->lpszFileName, lprgszFileSkipStrings)) {
                FreeAllFileContents(lpFC);
                continue;  // ignore this entry and continue with next file
            }

            lpszFullName = GetWholeFileName(lpFC, 0);
            if (lpszFullName == NULL) {
                lpShot->fIncomplete = TRUE;
                FreeAllFileContents(lpFC);
                return;
            }
            if (IsInSkipList(lpszFullName, lprgszFileSkipStrings)) {
                MYFREE(lpszFullName);
                FreeAllFileContents(lpFC);
                continue;  // ignore this entry and continue with next brother file
            }
            MYFREE(lpszFullName);
        }

        // Copy pointer to current file into caller's pointer
        if (NULL != lplpCaller) {
            *lplpCaller = lpFC;
        }

        // Increase dir/file count
        if (ISFILE(sFC.nFileAttributes)) {
            lpShot->stCounts.cFiles++;
        }
        else {
            lpShot->stCounts.cDirs++;
        }

        // Copy file data
        lpFC->nWriteDateTimeLow = sFC.nWriteDateTimeLow;
        lpFC->nWriteDateTimeHigh = sFC.nWriteDateTimeHigh;
        lpFC->nFileSizeLow = sFC.nFileSizeLow;
        lpFC->nFileSizeHigh = sFC.nFileSizeHigh;
        lpFC->nFileAttributes = sFC.nFileAttributes;
        if (fileheader.nFCVersion >= FILECONTENT_VERSION_4) {
            lpFC->nScanError = sFC.nScanError;
            if (lpFC->nScanError != 0)
                lpShot->cSkippedDirs++;
        }
        lpFC->nChkSumUnknown = TRUE;
        if (fileheader.nFCVersion >= FILECONTENT_VERSION_3
            && fileheader.nFCSize >= offsetof(SAVEFILECONTENT, fHashValid) + sizeof(sFC.fHashValid)
            && sFC.fHashValid == 1) {
            lpFC->nChkSum = ((QWORD)sFC.nHashHigh << 32) | sFC.nHashLow;
            lpFC->nChkSumUnknown = FALSE;
        }

        // Update counters display
        nCurrentTime = GetTickCount();
        if (REFRESHINTERVAL < (nCurrentTime - nLastTime)) {
            UI_UpdateCounters(asLangTexts[iszTextDir].lpszText, asLangTexts[iszTextFile].lpszText, lpShot->stCounts.cDirs, lpShot->stCounts.cFiles);
        }

        // ATTENTION!!! sFC will be INVALID from this point on, due to recursive calls
        // If the entry has childs, then do a recursive call for the first child
        // Pass this entry as father and "lpFirstSubFC" pointer for storing the first child's pointer
        if (0 != sFC.ofsFirstSubFile) {
            LoadFiles(lpShot, sFC.ofsFirstSubFile, lpFC, &lpFC->lpFirstSubFC);
        }

        // Set "lpBrotherFC" pointer for storing the next brother's pointer
        lplpCaller = &lpFC->lpBrotherFC;
    }
}


//--------------------------------------------------
// Load head file from HIVE file
//--------------------------------------------------
VOID LoadHeadFiles(LPREGSHOT lpShot, DWORD ofsHeadFile, LPHEADFILE* lplpCaller)
{
    LPHEADFILE lpHF;

    // Initialize save structures
    ZeroMemory(&sHF, sizeof(sHF));
    ZeroMemory(&sFC, sizeof(sFC));

    // Read all head files and their file contents
    for (; !lpShot->fIncomplete && 0 != ofsHeadFile; ofsHeadFile = sHF.ofsBrotherHeadFile) {
        // Copy SAVEHEADFILE to aligned memory block
        CopyMemory(&sHF, (lpFileBuffer + ofsHeadFile), fileheader.nHFSize);

        // Create new head file
        // put in a separate var for later use
        lpHF = MYALLOC0(sizeof(HEADFILE));
        if (lpHF == NULL) {
            lpShot->fIncomplete = TRUE;
            return;
        }

        // Copy pointer to current head file into caller's pointer
        if (NULL != lplpCaller) {
            *lplpCaller = lpHF;
        }

        // If the entry has file contents, then do a call for the first file content
        if (0 != sHF.ofsFirstFileContent) {
            LoadFiles(lpShot, sHF.ofsFirstFileContent, NULL, &lpHF->lpFirstFC);
        }

        // Set "lpBrotherHF" pointer for storing the next brother's pointer
        lplpCaller = &lpHF->lpBrotherHF;
    }
}


//--------------------------------------------------
// Walkthrough head file chain and collect it's first dirname to lpszDir
//--------------------------------------------------
BOOL FindDirChain(LPHEADFILE lpHF, LPTSTR lpszDir, size_t nBufferLen)
{
    size_t      nLen;
    size_t      nWholeLen;
    BOOL        fAddSeparator;
    BOOL        fAddBackslash;

    lpszDir[0] = (TCHAR)'\0';
    nWholeLen = 0;
    for (; NULL != lpHF; lpHF = lpHF->lpBrotherHF) {
        if ((NULL != lpHF->lpFirstFC)
            && (NULL != lpHF->lpFirstFC->lpszFileName)) {
            nLen = lpHF->lpFirstFC->cchFileName;
            if (0 < nLen) {
                fAddSeparator = FALSE;
                if (0 < nWholeLen) {
                    nLen++;
                    fAddSeparator = TRUE;
                }
                fAddBackslash = FALSE;
                if ((TCHAR)':' == lpHF->lpFirstFC->lpszFileName[lpHF->lpFirstFC->cchFileName - 1]) {
                    nLen++;
                    fAddBackslash = TRUE;
                }
                nWholeLen += nLen;
                if (nWholeLen < nBufferLen) {
                    if (fAddSeparator) {
                        _tcscat_s(lpszDir, EXTDIRLEN, TEXT(";"));
                    }
                    _tcscat_s(lpszDir, EXTDIRLEN, lpHF->lpFirstFC->lpszFileName);
                    if (fAddBackslash) {
                        _tcscat_s(lpszDir, EXTDIRLEN, TEXT("\\"));
                    }
                }
                else {
                    //nWholeLen -= nLen;
                    return FALSE;  // buffer too small, exit for-loop and routine
                }
            }
        }
    }
    return TRUE;
}


//--------------------------------------------------
// if two dir chains are the same
//--------------------------------------------------
BOOL DirChainMatch(LPHEADFILE lpHF1, LPHEADFILE lpHF2)
{
    TCHAR lpszDir1[EXTDIRLEN];
    TCHAR lpszDir2[EXTDIRLEN];

    FindDirChain(lpHF1, lpszDir1, EXTDIRLEN);  // Length in TCHARs incl. NULL char
    FindDirChain(lpHF2, lpszDir2, EXTDIRLEN);  // Length in TCHARs incl. NULL char

    if (0 != _tcsicmp(lpszDir1, lpszDir2)) {
        return FALSE;
    }

    return TRUE;
}