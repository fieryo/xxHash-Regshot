/*
    Copyright 2011-2018 Regshot Team
    Copyright 1999-2003,2007,2011 TiANWEi
    Copyright 2004 tulipfan

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
#include <stdint.h>
#include <stdlib.h>
#include "version.h"
#include <LMCons.h>  // for UNLEN define

LPTSTR lpszResultFileBaseName = REGSHOT_RESULT_FILE;

LPTSTR lpszFilter =
#ifdef _UNICODE
TEXT("Regshot Unicode hive files (*.hivu)\0*.hivu\0All files\0*.*\0\0");
#else
TEXT("Regshot ANSI hive files (*.hiv)\0*.hiv\0All files\0*.*\0\0");
#endif

// SBCS/MBCS signature (even in Unicode builds for backwards compatibility)
char szRegshotFileSignatureSBCS[] = "REGSHOTHIVE";
char szRegshotFileSignatureUTF16[] = "REGSHOTHIV2";  // use a number to define a file format not compatible with older releases (e.g. "3" could be UTF-32 or Big Endian)
#ifdef _UNICODE
#define szRegshotFileSignature szRegshotFileSignatureUTF16
#else
#define szRegshotFileSignature szRegshotFileSignatureSBCS
#endif

LPTSTR lpszRegshotFileDefExt =
#ifdef _UNICODE
TEXT("hivu");
#else
TEXT("hiv");
#endif

LPTSTR lpszValueDataIsNULL = TEXT(": (NULL!)");

LPTSTR lpszEmpty = TEXT("");

REGSHOT Shot1;
REGSHOT Shot2;

FILEHEADER fileheader;
FILEEXTRADATA fileextradata;
SAVEKEYCONTENT sKC;
SAVEVALUECONTENT sVC;

LPBYTE lpFileBuffer;
LPTSTR lpStringBuffer;
size_t nStringBufferSize;
LPBYTE lpDataBuffer;
size_t nDataBufferSize;
size_t nSourceSize;

#define MAX_SIGNATURE_LENGTH 12
#define REGSHOT_READ_BLOCK_SIZE 8192

// Compare result
COMPRESULTS CompareResult;

DWORD NBW;               // that is: NumberOfBytesWritten

HANDLE   hFileWholeReg;  // Handle of file regshot use
static BOOL fHiveWriteFailed;  // Any write to hFileWholeReg failed during SaveShot
FILETIME ftLastWrite;    // Filetime struct

// in regshot.ini, "UseLongRegHead" to control this
// 1.6 using long name, so in 1.8.1 add an option
LPTSTR lpszHKLMShort = TEXT("HKLM");
LPTSTR lpszHKLMLong = TEXT("HKEY_LOCAL_MACHINE");
#define CCH_HKLM_LONG  18

LPTSTR lpszHKUShort = TEXT("HKU");
LPTSTR lpszHKULong = TEXT("HKEY_USERS");
#define CCH_HKU_LONG  10

LONG nErrNo;


// VS 6 fix, may depend on PSDK/WSDK too
#ifndef _tcsnlen
size_t _tcsnlen(const TCHAR* str, size_t numberOfElements)
{
    size_t i;

    for (i = 0; i < numberOfElements; i++, str++) {
        if ((TCHAR)'\0' == *str) {
            break;
        }
    }

    return i;
}
#endif

// ----------------------------------------------------------------------
// Get whole registry key name from KEYCONTENT
// ----------------------------------------------------------------------
LPTSTR GetWholeKeyName(LPKEYCONTENT lpStartKC, BOOL fUseLongNames)
{
    LPKEYCONTENT lpKC;
    LPTSTR lpszName;
    LPTSTR lpszTail;
    size_t cchName;
    LPTSTR lpszKeyName;

    cchName = 0;
    for (lpKC = lpStartKC; NULL != lpKC; lpKC = lpKC->lpFatherKC) {
        if (NULL != lpKC->lpszKeyName) {
            if (lpKC->cchKeyName >= SIZE_MAX / sizeof(TCHAR) - cchName
                || CCH_HKLM_LONG >= SIZE_MAX / sizeof(TCHAR) - cchName)
                return NULL;
            if ((fUseLongNames) && (lpszHKLMShort == lpKC->lpszKeyName)) {
                cchName += CCH_HKLM_LONG;
            }
            else if ((fUseLongNames) && (lpszHKUShort == lpKC->lpszKeyName)) {
                cchName += CCH_HKU_LONG;
            }
            else {
                cchName += lpKC->cchKeyName;
            }
            cchName++;  // +1 char for backslash or NULL char
        }
    }
    if (0 == cchName) {  // at least create an empty string with NULL char
        cchName++;
    }

    lpszName = MYALLOC(cchName * sizeof(TCHAR));
    if (lpszName == NULL)
        return NULL;

    lpszTail = &lpszName[cchName - 1];
    lpszTail[0] = (TCHAR)'\0';

    for (lpKC = lpStartKC; NULL != lpKC; lpKC = lpKC->lpFatherKC) {
        if (NULL != lpKC->lpszKeyName) {
            if ((fUseLongNames) && (lpszHKLMShort == lpKC->lpszKeyName)) {
                cchName = CCH_HKLM_LONG;
                lpszKeyName = lpszHKLMLong;
            }
            else if ((fUseLongNames) && (lpszHKUShort == lpKC->lpszKeyName)) {
                cchName = CCH_HKU_LONG;
                lpszKeyName = lpszHKULong;
            }
            else {
                cchName = lpKC->cchKeyName;
                lpszKeyName = lpKC->lpszKeyName;
            }
            lpszTail -= cchName;
            memcpy(lpszTail, lpszKeyName, cchName * sizeof(TCHAR));
            if (lpszTail > lpszName) {
                *--lpszTail = (TCHAR)'\\';
            }
        }
    }

    return lpszName;
}


// ----------------------------------------------------------------------
// Get whole value name from VALUECONTENT
// ----------------------------------------------------------------------
LPTSTR GetWholeValueName(LPVALUECONTENT lpVC, BOOL fUseLongNames)
{
    LPKEYCONTENT lpKC;
    LPTSTR lpszName;
    LPTSTR lpszTail;
    size_t cchName;
    size_t cchValueName;
    LPTSTR lpszKeyName;

    cchValueName = 0;
    if (NULL != lpVC->lpszValueName) {
        cchValueName = lpVC->cchValueName;
    }
    if (cchValueName >= SIZE_MAX / sizeof(TCHAR))
        return NULL;
    cchName = cchValueName + 1;  // +1 char for NULL char

    for (lpKC = lpVC->lpFatherKC; NULL != lpKC; lpKC = lpKC->lpFatherKC) {
        if (NULL != lpKC->lpszKeyName) {
            if (lpKC->cchKeyName >= SIZE_MAX / sizeof(TCHAR) - cchName
                || CCH_HKLM_LONG >= SIZE_MAX / sizeof(TCHAR) - cchName)
                return NULL;
            if ((fUseLongNames) && (lpszHKLMShort == lpKC->lpszKeyName)) {
                cchName += CCH_HKLM_LONG;
            }
            else if ((fUseLongNames) && (lpszHKUShort == lpKC->lpszKeyName)) {
                cchName += CCH_HKU_LONG;
            }
            else {
                cchName += lpKC->cchKeyName;
            }
            cchName++;  // +1 char for backslash
        }
    }

    lpszName = MYALLOC0(cchName * sizeof(TCHAR));
    if (lpszName == NULL)
        return NULL;

    lpszTail = &lpszName[cchName - 1];
    lpszTail[0] = (TCHAR)'\0';
    if (NULL != lpVC->lpszValueName) {
        lpszTail -= cchValueName;
        memcpy(lpszTail, lpVC->lpszValueName, cchValueName * sizeof(TCHAR));
    }
    if (lpszTail > lpszName) {
        *--lpszTail = (TCHAR)'\\';
    }

    for (lpKC = lpVC->lpFatherKC; NULL != lpKC; lpKC = lpKC->lpFatherKC) {
        if (NULL != lpKC->lpszKeyName) {
            if ((fUseLongNames) && (lpszHKLMShort == lpKC->lpszKeyName)) {
                cchName = CCH_HKLM_LONG;
                lpszKeyName = lpszHKLMLong;
            }
            else if ((fUseLongNames) && (lpszHKUShort == lpKC->lpszKeyName)) {
                cchName = CCH_HKU_LONG;
                lpszKeyName = lpszHKULong;
            }
            else {
                cchName = lpKC->cchKeyName;
                lpszKeyName = lpKC->lpszKeyName;
            }
            lpszTail -= cchName;
            memcpy(lpszTail, lpszKeyName, cchName * sizeof(TCHAR));
            if (lpszTail > lpszName) {
                *--lpszTail = (TCHAR)'\\';
            }
        }
    }

    return lpszName;
}

// ----------------------------------------------------------------------
// Transform value content data from binary into string according
// to given conversion type (may differ from original type)
// Called by GetWholeValueData()
// ----------------------------------------------------------------------
LPTSTR TransData(LPVALUECONTENT lpVC, DWORD nConversionType, BOOL fForOutput)
{
    LPTSTR lpszValueData;
    LPDWORD lpDword;
    LPQWORD lpQword;
    DWORD nDwordCpu;
#if 1 == __LITTLE_ENDIAN__
    // no REG_QWORD_BIG_ENDIAN yet
#else
    QWORD nQwordCpu;
#endif

    lpszValueData = NULL;
    lpDword = NULL;
    lpQword = NULL;

    if (NULL == lpVC->lpValueData) {
        lpszValueData = MYALLOC0((_tcslen(lpszValueDataIsNULL) + 1) * sizeof(TCHAR));
        _tcscpy_s(lpszValueData, _tcslen(lpszValueDataIsNULL) + 1, lpszValueDataIsNULL);
    }
    else {
        DWORD cbData;
        DWORD ibCurrent;

        cbData = lpVC->cbData;

        switch (nConversionType) {
        case REG_SZ:
        case REG_EXPAND_SZ:
            // string value that can be displayed as a string
            // format  ": \"<string>\""
        {
            const TCHAR *src = (const TCHAR *)lpVC->lpValueData;
            size_t srcLen = 0;
            if (src != NULL) {
                srcLen = _tcsnlen(src, cbData / sizeof(TCHAR));
            }

            /* 3 = ": \"", 1 = closing '"', 1 = terminating NUL */
            size_t totalChars = 3 + srcLen + 1 + 1;
            lpszValueData = MYALLOC0(totalChars * sizeof(TCHAR));
            if (lpszValueData != NULL) {
                _tcscpy_s(lpszValueData, totalChars, TEXT(": \""));
                if (srcLen > 0) {
                    /* copy characters (multiply by sizeof(TCHAR) for bytes) */
                    memcpy(&lpszValueData[3], src, srcLen * sizeof(TCHAR));
                }
                lpszValueData[3 + srcLen] = TEXT('"');
                lpszValueData[3 + srcLen + 1] = TEXT('\0');
            }
            break;
        }

        case REG_MULTI_SZ:
            // multi string value that can be displayed as strings
            // format  ": \"<string>\", \"<string>\", \"<string>\", ...\0"
            // see http://msdn.microsoft.com/en-us/library/windows/desktop/ms724884.aspx
        {
            const TCHAR* src = (const TCHAR*)lpVC->lpValueData;
            size_t limit = cbData / sizeof(TCHAR);
            size_t offset, length, total = 5;
            BOOL first = TRUE;
            LPTSTR dst;

            for (offset = 0; offset < limit && src[offset] != 0;) {
                length = _tcsnlen(src + offset, limit - offset);
                if (length > (SIZE_MAX / sizeof(TCHAR)) - total - 4)
                    return NULL;
                total += length + (first ? 0 : 4);
                first = FALSE;
                offset += length;
                if (offset < limit)
                    ++offset;
            }
            lpszValueData = MYALLOC(total * sizeof(TCHAR));
            if (lpszValueData == NULL)
                return NULL;
            memcpy(lpszValueData, TEXT(": \""), 3 * sizeof(TCHAR));
            dst = lpszValueData + 3;
            first = TRUE;
            for (offset = 0; offset < limit && src[offset] != 0;) {
                length = _tcsnlen(src + offset, limit - offset);
                if (!first) {
                    memcpy(dst, TEXT("\", \""), 4 * sizeof(TCHAR));
                    dst += 4;
                }
                memcpy(dst, src + offset, length * sizeof(TCHAR));
                dst += length;
                first = FALSE;
                offset += length;
                if (offset < limit)
                    ++offset;
            }
            *dst++ = (TCHAR)'"';
            *dst = 0;
            break;
        }

#if 1 == __LITTLE_ENDIAN__
        case REG_DWORD_BIG_ENDIAN:
#else
        case REG_DWORD_LITTLE_ENDIAN:
#endif
            // convert DWORD with different endianness
            lpDword = &nDwordCpu;
            for (ibCurrent = 0; ibCurrent < sizeof(DWORD); ibCurrent++) {
                ((LPBYTE)&nDwordCpu)[ibCurrent] = lpVC->lpValueData[sizeof(DWORD) - 1 - ibCurrent];
            }

#if 1 == __LITTLE_ENDIAN__
        case REG_DWORD_LITTLE_ENDIAN:
#else
        case REG_DWORD_BIG_ENDIAN:
#endif
            // native DWORD that can be displayed as DWORD
            if (NULL == lpDword) {
                lpDword = (LPDWORD)lpVC->lpValueData;
            }
            // format  ": 0xXXXXXXXX\0"
            lpszValueData = MYALLOC0((1 + 3 + 8 + 1) * sizeof(TCHAR));
            _tcscpy_s(lpszValueData, 1 + 3 + 8 + 1, TEXT(":"));
            if (NULL != lpVC->lpValueData) {
                _sntprintf_s(lpszValueData + 1, (1 + 3 + 8 + 1), (3 + 8 + 1), TEXT(" 0x%08X\0"), *lpDword);
            }
            break;

#if 1 == __LITTLE_ENDIAN__
            //case REG_QWORD_BIG_ENDIAN:
#else
        case REG_QWORD_LITTLE_ENDIAN:
#endif
#if 1 == __LITTLE_ENDIAN__
            // no REG_QWORD_BIG_ENDIAN yet
#else
            // convert QWORD with different endianness
            lpQword = &nQwordCpu;
            for (ibCurrent = 0; ibCurrent < sizeof(QWORD); i++) {
                ((LPBYTE)&nQwordCpu)[ibCurrent] = lpVC->lpValueData[sizeof(QWORD) - ibCurrent - ibCurrent];
            }
#endif

#if 1 == __LITTLE_ENDIAN__
        case REG_QWORD_LITTLE_ENDIAN:
#else
            //case REG_QWORD_BIG_ENDIAN:
#endif
                // native QWORD that can be displayed as QWORD
            if (NULL == lpQword) {
                lpQword = (LPQWORD)lpVC->lpValueData;
            }
            // format  ": 0xXXXXXXXXXXXXXXXX\0"
            lpszValueData = MYALLOC0((1 + 3 + 16 + 1) * sizeof(TCHAR));
            _tcscpy_s(lpszValueData, 1 + 3 + 16 + 1, TEXT(":"));
            if (NULL != lpVC->lpValueData) {
                _sntprintf_s(lpszValueData + 1, (1 + 3 + 16 + 1), (3 + 16 + 1), TEXT(" 0x%016I64X\0"), *lpQword);
            }
            break;

        default:
            // display value as hex bytes
            // format ":[ xx][ xx]...[ xx][ ...]\0"
            if ((fForOutput) && (0 < cbOutBinaryMax) && (cbData > cbOutBinaryMax)) {
                cbData = cbOutBinaryMax;
            }
            if ((size_t)cbData > (SIZE_MAX / sizeof(TCHAR) - 6) / 3)
                return NULL;
            size_t cchValueData = 1 + ((size_t)cbData * 3) + 4 + 1;
            lpszValueData = MYALLOC0(cchValueData * sizeof(TCHAR));
            if (lpszValueData == NULL)
                return NULL;
            _tcscpy_s(lpszValueData, cchValueData, TEXT(":"));
            for (ibCurrent = 0; ibCurrent < cbData; ibCurrent++) {
                _sntprintf_s(lpszValueData + (1 + (ibCurrent * 3)), cchValueData - (1 + (ibCurrent * 3)), 4, TEXT(" %02X\0"), *(lpVC->lpValueData + ibCurrent));
            }
            if (cbData != lpVC->cbData) {
                _sntprintf_s(lpszValueData + (1 + (ibCurrent * 3)), cchValueData - (1 + (ibCurrent * 3)), 4, TEXT(" ...\0"));
            }
        }
    }
      
    return lpszValueData;
}


// ----------------------------------------------------------------------
// Get value data from value content as string
// Check for special cases to call TransData() properly
// ----------------------------------------------------------------------
LPTSTR GetWholeValueData(LPVALUECONTENT lpVC, BOOL fForOutput)
{
    LPTSTR lpszValueData;

    lpszValueData = NULL;

    if (NULL == lpVC->lpValueData) {
        lpszValueData = TransData(lpVC, REG_BINARY, fForOutput);
    }
    else {
        DWORD cbData;
        size_t cchMax;
        size_t cchActual;

        cbData = lpVC->cbData;

        switch (lpVC->nTypeCode) {
        case REG_SZ:
        case REG_EXPAND_SZ:
        case REG_MULTI_SZ:
            // string values
            // check for hidden bytes after string[s]
            cchMax = cbData / sizeof(TCHAR);  // convert byte count to char count
            if (REG_MULTI_SZ == lpVC->nTypeCode) {
                // search double null chars
                for (cchActual = 0; cchActual < cchMax; cchActual++) {
                    if (0 != ((LPTSTR)lpVC->lpValueData)[cchActual]) {
                        continue;
                    }

                    cchActual++;
                    if (cchActual >= cchMax) {  // special case: incorrectly terminated
                        break;
                    }

                    if (0 != ((LPTSTR)lpVC->lpValueData)[cchActual]) {
                        continue;
                    }

                    // found
                    cchActual++;
                    break;
                }
            }
            else {
                cchActual = _tcsnlen((LPTSTR)lpVC->lpValueData, cchMax);
                if (cchActual < cchMax) {
                    cchActual++;  // account for null char
                }
            }
            if ((cchActual * sizeof(TCHAR)) == cbData) {
                lpszValueData = TransData(lpVC, lpVC->nTypeCode, fForOutput);
            }
            else {
                lpszValueData = TransData(lpVC, REG_BINARY, fForOutput);
            }
            break;

        case REG_DWORD_LITTLE_ENDIAN:
        case REG_DWORD_BIG_ENDIAN:
            // DWORD values
            if (sizeof(DWORD) == cbData) {
                lpszValueData = TransData(lpVC, lpVC->nTypeCode, fForOutput);
            }
            else {
                lpszValueData = TransData(lpVC, REG_BINARY, fForOutput);
            }
            break;

        case REG_QWORD_LITTLE_ENDIAN:
            //case REG_QWORD_BIG_ENDIAN:
            // QWORD values
            if (sizeof(QWORD) == cbData) {
                lpszValueData = TransData(lpVC, lpVC->nTypeCode, fForOutput);
            }
            else {
                lpszValueData = TransData(lpVC, REG_BINARY, fForOutput);
            }
            break;

        default:
            lpszValueData = TransData(lpVC, REG_BINARY, fForOutput);
        }
    }

    return lpszValueData;
}


//-------------------------------------------------------------
// Routine to create new comparison result, distribute to different pointers
//-------------------------------------------------------------
VOID CreateNewResult(DWORD nActionType, LPVOID lpContentOld, LPVOID lpContentNew)
{
    LPCOMPRESULT lpCR;

    lpCR = (LPCOMPRESULT)MYALLOC0(sizeof(COMPRESULT));
    lpCR->lpContentOld = lpContentOld;
    lpCR->lpContentNew = lpContentNew;

    switch (nActionType) {
    case KEYDEL:
        (NULL == CompareResult.stCRHeads.lpCRKeyDeleted) ? (CompareResult.stCRHeads.lpCRKeyDeleted = lpCR) : (CompareResult.stCRCurrent.lpCRKeyDeleted->lpNextCR = lpCR);
        CompareResult.stCRCurrent.lpCRKeyDeleted = lpCR;
        break;
    case KEYADD:
        (NULL == CompareResult.stCRHeads.lpCRKeyAdded) ? (CompareResult.stCRHeads.lpCRKeyAdded = lpCR) : (CompareResult.stCRCurrent.lpCRKeyAdded->lpNextCR = lpCR);
        CompareResult.stCRCurrent.lpCRKeyAdded = lpCR;
        break;
    case VALDEL:
        (NULL == CompareResult.stCRHeads.lpCRValDeleted) ? (CompareResult.stCRHeads.lpCRValDeleted = lpCR) : (CompareResult.stCRCurrent.lpCRValDeleted->lpNextCR = lpCR);
        CompareResult.stCRCurrent.lpCRValDeleted = lpCR;
        break;
    case VALADD:
        (NULL == CompareResult.stCRHeads.lpCRValAdded) ? (CompareResult.stCRHeads.lpCRValAdded = lpCR) : (CompareResult.stCRCurrent.lpCRValAdded->lpNextCR = lpCR);
        CompareResult.stCRCurrent.lpCRValAdded = lpCR;
        break;
    case VALMODI:
        (NULL == CompareResult.stCRHeads.lpCRValModified) ? (CompareResult.stCRHeads.lpCRValModified = lpCR) : (CompareResult.stCRCurrent.lpCRValModified->lpNextCR = lpCR);
        CompareResult.stCRCurrent.lpCRValModified = lpCR;
        break;
    case DIRDEL:
        (NULL == CompareResult.stCRHeads.lpCRDirDeleted) ? (CompareResult.stCRHeads.lpCRDirDeleted = lpCR) : (CompareResult.stCRCurrent.lpCRDirDeleted->lpNextCR = lpCR);
        CompareResult.stCRCurrent.lpCRDirDeleted = lpCR;
        break;
    case DIRADD:
        (NULL == CompareResult.stCRHeads.lpCRDirAdded) ? (CompareResult.stCRHeads.lpCRDirAdded = lpCR) : (CompareResult.stCRCurrent.lpCRDirAdded->lpNextCR = lpCR);
        CompareResult.stCRCurrent.lpCRDirAdded = lpCR;
        break;
    case DIRMODI:
        (NULL == CompareResult.stCRHeads.lpCRDirModified) ? (CompareResult.stCRHeads.lpCRDirModified = lpCR) : (CompareResult.stCRCurrent.lpCRDirModified->lpNextCR = lpCR);
        CompareResult.stCRCurrent.lpCRDirModified = lpCR;
        break;
    case FILEDEL:
        (NULL == CompareResult.stCRHeads.lpCRFileDeleted) ? (CompareResult.stCRHeads.lpCRFileDeleted = lpCR) : (CompareResult.stCRCurrent.lpCRFileDeleted->lpNextCR = lpCR);
        CompareResult.stCRCurrent.lpCRFileDeleted = lpCR;
        break;
    case FILEADD:
        (NULL == CompareResult.stCRHeads.lpCRFileAdded) ? (CompareResult.stCRHeads.lpCRFileAdded = lpCR) : (CompareResult.stCRCurrent.lpCRFileAdded->lpNextCR = lpCR);
        CompareResult.stCRCurrent.lpCRFileAdded = lpCR;
        break;
    case FILEMODI:
        (NULL == CompareResult.stCRHeads.lpCRFileModified) ? (CompareResult.stCRHeads.lpCRFileModified = lpCR) : (CompareResult.stCRCurrent.lpCRFileModified->lpNextCR = lpCR);
        CompareResult.stCRCurrent.lpCRFileModified = lpCR;
        break;
    }
}


//-------------------------------------------------------------
// Convert content to result strings
//-------------------------------------------------------------
size_t ResultToString(LPTSTR rgszResultStrings[], size_t iResultStringsMac, DWORD nActionType, LPVOID lpContent, BOOL fNewContent)
{
    LPTSTR lpszName;
    LPTSTR lpszData;
    LPTSTR lpszOldData;
    size_t cchData = 0;
    size_t iResultStringsNew = 0;
    size_t iResultStringsTemp1 = 0;

    iResultStringsNew = iResultStringsMac;

    if ((KEYDEL == nActionType) || (KEYADD == nActionType)) {
        // create result
        // name only
        if (iResultStringsNew < MAX_RESULT_STRINGS) {
            rgszResultStrings[iResultStringsNew] = GetWholeKeyName(lpContent, fUseLongRegHead);
            iResultStringsNew++;
        }
    }
    else if ((VALDEL == nActionType) || (VALADD == nActionType) || (VALMODI == nActionType)) {
        // name
        lpszName = GetWholeValueName(lpContent, fUseLongRegHead);
        // data
        lpszData = GetWholeValueData(lpContent, TRUE);
        cchData = 0;
        if (NULL != lpszData) {
            cchData = _tcslen(lpszData);
        }
        // create result
        if (iResultStringsNew < MAX_RESULT_STRINGS) {
            const size_t cchResultStringsNew = _tcslen(lpszName) + cchData + 1;
            rgszResultStrings[iResultStringsNew] = MYALLOC0((cchResultStringsNew) * sizeof(TCHAR));
            _tcscpy_s(rgszResultStrings[iResultStringsNew], cchResultStringsNew, lpszName);
            if (NULL != lpszData) {
                _tcscat_s(rgszResultStrings[iResultStringsNew], cchResultStringsNew, lpszData);
            }
            iResultStringsNew++;
        }
        MYFREE(lpszName);
        if (NULL != lpszData) {
            MYFREE(lpszData);
        }
    }
    else if ((DIRDEL == nActionType) || (DIRADD == nActionType) || (DIRMODI == nActionType)) {
        // create result (1st line)
        // name only
        if ((!fNewContent) || (0 >= iResultStringsMac)) {
            if (iResultStringsNew < MAX_RESULT_STRINGS) {
                rgszResultStrings[iResultStringsNew] = GetWholeFileName(lpContent, 0);
                iResultStringsNew++;
            }
        }
        // attributes
        lpszData = MYALLOC0(SIZEOF_RESULT_DATA * sizeof(TCHAR));
        cchData = _sntprintf_s(lpszData, SIZEOF_RESULT_DATA, SIZEOF_RESULT_DATA, TEXT("0x%08X\0"), ((LPFILECONTENT)lpContent)->nFileAttributes);
        // create result (2nd line)
        // add to previous line if old and new data present
        iResultStringsTemp1 = iResultStringsNew;
        lpszOldData = NULL;

        if ((fNewContent) && (0 < iResultStringsMac)) {
            iResultStringsTemp1 = iResultStringsMac - 1;
            lpszOldData = rgszResultStrings[iResultStringsTemp1];
            cchData += _tcslen(lpszOldData) + 5;  // length in chars of separator between old and new content
        }
        if (iResultStringsTemp1 < MAX_RESULT_STRINGS) {
            rgszResultStrings[iResultStringsTemp1] = MYALLOC0((cchData + 1) * sizeof(TCHAR));
            if ((fNewContent) && (0 < iResultStringsMac)) {
                _tcscpy_s(rgszResultStrings[iResultStringsTemp1], cchData + 1, lpszOldData);
                _tcscat_s(rgszResultStrings[iResultStringsTemp1], cchData + 1, TEXT(" --> "));
            }
            else {
                /* Null-terminate the newly allocated buffer at the last valid index.
                   Use iResultStringsTemp1 (the index we allocated) and cchData (last index),
                   not iResultStringsNew or cchData+1 which were off-by-one/wrong-index. */
                rgszResultStrings[iResultStringsTemp1][cchData] = (TCHAR)'\0';
            }
            _tcscat_s(rgszResultStrings[iResultStringsTemp1], cchData + 1, lpszData);
            if (iResultStringsTemp1 >= iResultStringsMac) {
                iResultStringsNew++;
            }
        }
        MYFREE(lpszData);
        if (NULL != lpszOldData) {
            MYFREE(lpszOldData);
        }
    }
    else if ((FILEDEL == nActionType) || (FILEADD == nActionType) || (FILEMODI == nActionType)) {
        SYSTEMTIME stFile;
        FILETIME ftFile;
        LARGE_INTEGER cbFile;
        // create result (1st line)
        // name only
        if ((!fNewContent) || (0 >= iResultStringsMac)) {
            if (iResultStringsNew < MAX_RESULT_STRINGS) {
                rgszResultStrings[iResultStringsNew] = GetWholeFileName(lpContent, 0);
                iResultStringsNew++;
            }
        }
        // last write time, attributes, size
        ZeroMemory(&ftFile, sizeof(ftFile));
        ftFile.dwLowDateTime = ((LPFILECONTENT)lpContent)->nWriteDateTimeLow;
        ftFile.dwHighDateTime = ((LPFILECONTENT)lpContent)->nWriteDateTimeHigh;
        ZeroMemory(&stFile, sizeof(stFile));
        FileTimeToSystemTime(&ftFile, &stFile);
        ZeroMemory(&cbFile, sizeof(cbFile));
        cbFile.LowPart = ((LPFILECONTENT)lpContent)->nFileSizeLow;
        cbFile.HighPart = ((LPFILECONTENT)lpContent)->nFileSizeHigh;
        lpszData = MYALLOC0(SIZEOF_RESULT_DATA * sizeof(TCHAR));
        /* Use cbFile.QuadPart and a 64-bit format specifier to avoid passing a LARGE_INTEGER struct to printf. */
        cchData = _sntprintf_s(lpszData, SIZEOF_RESULT_DATA, SIZEOF_RESULT_DATA, TEXT("%04d-%02d-%02d %02d:%02d:%02d, 0x%08X, %lld\0"),
            stFile.wYear, stFile.wMonth, stFile.wDay,
            stFile.wHour, stFile.wMinute, stFile.wSecond,
            ((LPFILECONTENT)lpContent)->nFileAttributes, (long long)cbFile.QuadPart);
        // create result (2nd/3rd line)
        if (iResultStringsNew < MAX_RESULT_STRINGS) {
            rgszResultStrings[iResultStringsNew] = lpszData;
            iResultStringsNew++;
        }
    }
    else {
        // TODO: error message and handling
    }

    return iResultStringsNew;
}


//-------------------------------------------------------------
// Routine to free all comparison results (release memory)
//-------------------------------------------------------------
VOID FreeAllCompResults(LPCOMPRESULT lpCR)
{
    LPCOMPRESULT lpNextCR;

    for (; NULL != lpCR; lpCR = lpNextCR) {
        // Save pointer in local variable
        lpNextCR = lpCR->lpNextCR;

        // Increase count
        cCurrent++;

        // Update progress bar display
        if (0 != cEnd) {
            nCurrentTime = GetTickCount();
            if (REFRESHINTERVAL < (nCurrentTime - nLastTime)) {
                UI_UpdateProgressBar();
            }
        }

        // Free compare result itself
        MYFREE(lpCR);
    }
}


// ----------------------------------------------------------------------
// Free all compare results
// ----------------------------------------------------------------------
VOID FreeCompareResult(void)
{
    FreeAllCompResults(CompareResult.stCRHeads.lpCRKeyDeleted);
    FreeAllCompResults(CompareResult.stCRHeads.lpCRKeyAdded);
    FreeAllCompResults(CompareResult.stCRHeads.lpCRValDeleted);
    FreeAllCompResults(CompareResult.stCRHeads.lpCRValAdded);
    FreeAllCompResults(CompareResult.stCRHeads.lpCRValModified);
    FreeAllCompResults(CompareResult.stCRHeads.lpCRDirDeleted);
    FreeAllCompResults(CompareResult.stCRHeads.lpCRDirAdded);
    FreeAllCompResults(CompareResult.stCRHeads.lpCRDirModified);
    FreeAllCompResults(CompareResult.stCRHeads.lpCRFileDeleted);
    FreeAllCompResults(CompareResult.stCRHeads.lpCRFileAdded);
    FreeAllCompResults(CompareResult.stCRHeads.lpCRFileModified);

    ZeroMemory(&CompareResult, sizeof(CompareResult));
}


//-------------------------------------------------------------
// Registry comparison engine
//-------------------------------------------------------------
static int CompareIndexNames(LPCTSTR left, LPCTSTR right)
{
    if (left == right)
        return 0;
    if (left == NULL)
        return -1;
    if (right == NULL)
        return 1;
    return _tcsicmp(left, right);
}

static int __cdecl CompareIndexEntries(const void* left, const void* right)
{
    const NAMEINDEXENTRY* a = left;
    const NAMEINDEXENTRY* b = right;
    int result = CompareIndexNames(a->name, b->name);

    if (result != 0)
        return result;
    if (a->type != b->type)
        return a->type < b->type ? -1 : 1;
    return a->order < b->order ? -1 : a->order != b->order;
}

NAMEINDEXENTRY* AllocateNameIndex(size_t count)
{
    NAMEINDEXENTRY* entries;

    if (count < 2)
        return NULL;
    entries = count <= SIZE_MAX / sizeof(*entries) ? MYALLOC(count * sizeof(*entries)) : NULL;
    if (entries == NULL)
        OutputDebugString(TEXT("Comparison: name index allocation failed; using sequential matching.\n"));
    return entries;
}

VOID SortNameIndex(NAMEINDEXENTRY* entries, size_t count)
{
    if (entries != NULL)
        qsort(entries, count, sizeof(*entries), CompareIndexEntries);
}

LPVOID FindNameIndex(NAMEINDEXENTRY* entries, size_t count, LPCTSTR name, DWORD type)
{
    size_t low = 0, high = count;

    while (low < high) {
        size_t mid = low + (high - low) / 2;
        int result = CompareIndexNames(entries[mid].name, name);

        if (result < 0 || (result == 0 && entries[mid].type < type))
            low = mid + 1;
        else
            high = mid;
    }
    for (; low < count && entries[low].type == type
        && CompareIndexNames(entries[low].name, name) == 0; ++low) {
        if (*entries[low].match == NOMATCH)
            return entries[low].content;
    }
    return NULL;
}

static NAMEINDEXENTRY* IndexRegKeys(LPKEYCONTENT first, size_t* count)
{
    LPKEYCONTENT key;
    NAMEINDEXENTRY* entries;
    size_t i = 0;

    *count = 0;
    for (key = first; key != NULL; key = key->lpBrotherKC)
        ++*count;
    entries = AllocateNameIndex(*count);
    if (entries != NULL) {
        for (key = first; key != NULL; key = key->lpBrotherKC, ++i) {
            entries[i].name = key->lpszKeyName;
            entries[i].type = 0;
            entries[i].content = key;
            entries[i].match = &key->fKeyMatch;
            entries[i].order = i;
        }
        SortNameIndex(entries, *count);
    }
    return entries;
}

static NAMEINDEXENTRY* IndexRegValues(LPVALUECONTENT first, size_t* count)
{
    LPVALUECONTENT value;
    NAMEINDEXENTRY* entries;
    size_t i = 0;

    *count = 0;
    for (value = first; value != NULL; value = value->lpBrotherVC)
        ++*count;
    entries = AllocateNameIndex(*count);
    if (entries != NULL) {
        for (value = first; value != NULL; value = value->lpBrotherVC, ++i) {
            entries[i].name = value->lpszValueName;
            entries[i].type = value->nTypeCode;
            entries[i].content = value;
            entries[i].match = &value->fValueMatch;
            entries[i].order = i;
        }
        SortNameIndex(entries, *count);
    }
    return entries;
}

VOID CompareRegKeys(LPKEYCONTENT lpStartKC1, LPKEYCONTENT lpStartKC2)
{
    LPKEYCONTENT lpKC1;
    LPKEYCONTENT lpKC2;
    size_t keyCount = 0;
    NAMEINDEXENTRY* keyIndex = lpStartKC1 != NULL ? IndexRegKeys(lpStartKC2, &keyCount) : NULL;

    // Compare keys
    for (lpKC1 = lpStartKC1; NULL != lpKC1; lpKC1 = lpKC1->lpBrotherKC) {
        CompareResult.stcCompared.cKeys++;
        // Find a matching key for KC1
        for (lpKC2 = keyIndex != NULL ? FindNameIndex(keyIndex, keyCount, lpKC1->lpszKeyName, 0) : lpStartKC2;
            NULL != lpKC2; lpKC2 = keyIndex != NULL ? NULL : lpKC2->lpBrotherKC) {
            // skip KC2 if already matched
            if (NOMATCH != lpKC2->fKeyMatch) {
                continue;
            }
            // skip KC2 if names do *not* match (ATTENTION: test for match, THEN negate)
            if (!(
                (lpKC1->lpszKeyName == lpKC2->lpszKeyName)
                || ((NULL != lpKC1->lpszKeyName) && (NULL != lpKC2->lpszKeyName) && (0 == _tcsicmp(lpKC1->lpszKeyName, lpKC2->lpszKeyName)))
                )) {
                continue;
            }

            // Same key name of KC1 found in KC2! Mark KC2 as matched to skip it for the next KC1, then compare their values and sub keys!
            lpKC2->fKeyMatch = ISMATCH;
            if (lpKC1->nScanError != 0 || lpKC2->nScanError != 0)
                break;

            // Extra local block to reduce stack usage due to recursive calls
            {
                LPVALUECONTENT lpVC1;
                LPVALUECONTENT lpVC2;
                size_t valueCount = 0;
                NAMEINDEXENTRY* valueIndex = lpKC1->lpFirstVC != NULL
                    ? IndexRegValues(lpKC2->lpFirstVC, &valueCount) : NULL;

                // Compare values
                for (lpVC1 = lpKC1->lpFirstVC; NULL != lpVC1; lpVC1 = lpVC1->lpBrotherVC) {
                    CompareResult.stcCompared.cValues++;
                    // Find a matching value for VC1
                    for (lpVC2 = valueIndex != NULL
                        ? FindNameIndex(valueIndex, valueCount, lpVC1->lpszValueName, lpVC1->nTypeCode) : lpKC2->lpFirstVC;
                        NULL != lpVC2; lpVC2 = valueIndex != NULL ? NULL : lpVC2->lpBrotherVC) {
                        // skip VC2 if already matched
                        if (NOMATCH != lpVC2->fValueMatch) {
                            continue;
                        }
                        // skip VC2 if types do *not* match (even if same name then interpret as deleted+added)
                        if (lpVC1->nTypeCode != lpVC2->nTypeCode) {
                            continue;
                        }
                        // skip VC2 if names do *not* match (ATTENTION: test for match, THEN negate)
                        if (!(
                            (lpVC1->lpszValueName == lpVC2->lpszValueName)
                            || ((NULL != lpVC1->lpszValueName) && (NULL != lpVC2->lpszValueName) && (0 == _tcsicmp(lpVC1->lpszValueName, lpVC2->lpszValueName)))
                            )) {
                            continue;
                        }

                        // Same value type and name of VC1 found in VC2, so compare their size and data
                        if ((lpVC1->cbData == lpVC2->cbData)
                            && ((lpVC1->lpValueData == lpVC2->lpValueData)
                                || ((NULL != lpVC1->lpValueData) && (NULL != lpVC2->lpValueData) && (0 == memcmp(lpVC1->lpValueData, lpVC2->lpValueData, lpVC1->cbData)))
                                )) {
                            // Same value data of VC1 found in VC2
                            lpVC2->fValueMatch = ISMATCH;
                        }
                        else {
                            // Value data differ, so value is modified
                            lpVC2->fValueMatch = ISMODI;
                            CompareResult.stcChanged.cValues++;
                            CompareResult.stcModified.cValues++;
                            CreateNewResult(VALMODI, lpVC1, lpVC2);
                        }
                        break;
                    }
                    if (NULL == lpVC2) {
                        // VC1 has no match in KC2, so VC1 is a deleted value
                        CompareResult.stcChanged.cValues++;
                        CompareResult.stcDeleted.cValues++;
                        CreateNewResult(VALDEL, lpVC1, NULL);
                    }
                }
                // After looping all values of KC1, do an extra loop over all KC2 values and check previously set match flags to determine added values
                for (lpVC2 = lpKC2->lpFirstVC; NULL != lpVC2; lpVC2 = lpVC2->lpBrotherVC) {
                    // skip VC2 if already matched
                    if (NOMATCH != lpVC2->fValueMatch) {
                        continue;
                    }

                    CompareResult.stcCompared.cValues++;

                    // VC2 has no match in KC1, so VC2 is an added value
                    CompareResult.stcChanged.cValues++;
                    CompareResult.stcAdded.cValues++;
                    CreateNewResult(VALADD, NULL, lpVC2);
                }
                if (valueIndex != NULL)
                    MYFREE(valueIndex);
            }  // End of extra local block

            // Compare sub keys if any
            if ((NULL != lpKC1->lpFirstSubKC) || (NULL != lpKC2->lpFirstSubKC)) {
                CompareRegKeys(lpKC1->lpFirstSubKC, lpKC2->lpFirstSubKC);
            }
            break;
        }
        if (NULL == lpKC2) {
            // KC1 has no matching KC2, so KC1 is a deleted key
            CompareResult.stcChanged.cKeys++;
            CompareResult.stcDeleted.cKeys++;
            CreateNewResult(KEYDEL, lpKC1, NULL);
            // Extra local block to reduce stack usage due to recursive calls
            {
                LPVALUECONTENT lpVC1;

                for (lpVC1 = lpKC1->lpFirstVC; NULL != lpVC1; lpVC1 = lpVC1->lpBrotherVC) {
                    CompareResult.stcCompared.cValues++;
                    CompareResult.stcChanged.cValues++;
                    CompareResult.stcDeleted.cValues++;
                    CreateNewResult(VALDEL, lpVC1, NULL);
                }
            }  // End of extra local block

            // "Compare"/Log sub keys if any
            if (NULL != lpKC1->lpFirstSubKC) {
                CompareRegKeys(lpKC1->lpFirstSubKC, NULL);
            }
        }
    }
    // After looping all KC1 keys, do an extra loop over all KC2 keys and check previously set match flags to determine added keys
    for (lpKC2 = lpStartKC2; NULL != lpKC2; lpKC2 = lpKC2->lpBrotherKC) {
        // skip KC2 if already matched
        if (NOMATCH != lpKC2->fKeyMatch) {
            continue;
        }

        // KC2 has no matching KC1, so KC2 is an added key
        CompareResult.stcCompared.cKeys++;
        CompareResult.stcChanged.cKeys++;
        CompareResult.stcAdded.cKeys++;
        CreateNewResult(KEYADD, NULL, lpKC2);
        // Extra local block to reduce stack usage due to recursive calls
        {
            LPVALUECONTENT lpVC2;

            for (lpVC2 = lpKC2->lpFirstVC; NULL != lpVC2; lpVC2 = lpVC2->lpBrotherVC) {
                CompareResult.stcCompared.cValues++;
                CompareResult.stcChanged.cValues++;
                CompareResult.stcAdded.cValues++;
                CreateNewResult(VALADD, NULL, lpVC2);
            }
        }  // End of extra local block

        // "Compare"/Log sub keys if any
        if (NULL != lpKC2->lpFirstSubKC) {
            CompareRegKeys(NULL, lpKC2->lpFirstSubKC);
        }
    }
    if (keyIndex != NULL)
        MYFREE(keyIndex);

    // Update counters display
    nCurrentTime = GetTickCount();
    if (REFRESHINTERVAL < (nCurrentTime - nLastTime)) {
        UI_UpdateCounters(asLangTexts[iszTextKey].lpszText, asLangTexts[iszTextValue].lpszText, CompareResult.stcCompared.cKeys, CompareResult.stcCompared.cValues);
    }
}


//------------------------------------------------------------
// Routine to call registry/file comparison engine
//------------------------------------------------------------
VOID CompareShots(VOID)
{
    if (!DirChainMatch(Shot1.lpHF, Shot2.lpHF)) {
#ifdef _WINDOWS
        MessageBox(hWnd, TEXT("Found two shots with different DIR chain! (or with different order)\r\nYou can continue, but file comparison result would be abnormal!"), asLangTexts[iszTextWarning].lpszText, MB_ICONWARNING);  //TODO: I18N, create text index and translate
#endif
    }

    // Initialize result and markers
    cEnd = 0;
    FreeCompareResult();
    CompareResult.lpShot1 = &Shot1;
    CompareResult.lpShot2 = &Shot2;
    ClearRegKeyMatchFlags(Shot1.lpHKLM);
    ClearRegKeyMatchFlags(Shot2.lpHKLM);
    ClearRegKeyMatchFlags(Shot1.lpHKU);
    ClearRegKeyMatchFlags(Shot2.lpHKU);
    ClearHeadFileMatchFlags(Shot1.lpHF);
    ClearHeadFileMatchFlags(Shot2.lpHF);

    // Setup GUI for comparing...
    UI_InitCounters();

    // Compare HKLM
    if ((NULL != CompareResult.lpShot1->lpHKLM) || (NULL != CompareResult.lpShot2->lpHKLM)) {
        CompareRegKeys(CompareResult.lpShot1->lpHKLM, CompareResult.lpShot2->lpHKLM);

        // Update counters display (keys/values final)
        nCurrentTime = GetTickCount();
        UI_UpdateCounters(asLangTexts[iszTextKey].lpszText, asLangTexts[iszTextValue].lpszText, CompareResult.stcCompared.cKeys, CompareResult.stcCompared.cValues);
    }

    // Compare HKU
    if ((NULL != CompareResult.lpShot1->lpHKU) || (NULL != CompareResult.lpShot2->lpHKU)) {
        CompareRegKeys(CompareResult.lpShot1->lpHKU, CompareResult.lpShot2->lpHKU);

        // Update counters display (keys/values final)
        nCurrentTime = GetTickCount();
        UI_UpdateCounters(asLangTexts[iszTextKey].lpszText, asLangTexts[iszTextValue].lpszText, CompareResult.stcCompared.cKeys, CompareResult.stcCompared.cValues);
    }

    // Compare HEADFILEs v1.8.1
    if ((NULL != CompareResult.lpShot1->lpHF) || (NULL != CompareResult.lpShot2->lpHF)) {
        CompareHeadFiles(CompareResult.lpShot1->lpHF, CompareResult.lpShot2->lpHF);

        // Update counters display (dirs/files final)
        nCurrentTime = GetTickCount();
        UI_UpdateCounters(asLangTexts[iszTextDir].lpszText, asLangTexts[iszTextFile].lpszText, CompareResult.stcCompared.cDirs, CompareResult.stcCompared.cFiles);
    }

    // Get total count of all items
    CompareResult.stcCompared.cAll = CompareResult.stcCompared.cKeys
        + CompareResult.stcCompared.cValues
        + CompareResult.stcCompared.cDirs
        + CompareResult.stcCompared.cFiles;
    CompareResult.stcChanged.cAll = CompareResult.stcChanged.cKeys
        + CompareResult.stcChanged.cValues
        + CompareResult.stcChanged.cDirs
        + CompareResult.stcChanged.cFiles;
    CompareResult.stcDeleted.cAll = CompareResult.stcDeleted.cKeys
        + CompareResult.stcDeleted.cValues
        + CompareResult.stcDeleted.cDirs
        + CompareResult.stcDeleted.cFiles;
    CompareResult.stcAdded.cAll = CompareResult.stcAdded.cKeys
        + CompareResult.stcAdded.cValues
        + CompareResult.stcAdded.cDirs
        + CompareResult.stcAdded.cFiles;
    CompareResult.stcModified.cAll = CompareResult.stcModified.cKeys
        + CompareResult.stcModified.cValues
        + CompareResult.stcModified.cDirs
        + CompareResult.stcModified.cFiles;
    CompareResult.fFilled = TRUE;

    UI_ShowHideCounters(SW_HIDE);
}


//------------------------------------------------------------
// Routine to output comparison result
//------------------------------------------------------------
BOOL OutputComparisonResult(VOID)
{
    BOOL   fAsHTML;
    LPTSTR lpszBuffer;
    LPTSTR lpszExtension;
    LPTSTR lpszDestFileName;
    DWORD  nBufferSize = 2048;
    size_t cchString;

    // Setup GUI for saving...
    cEnd = CompareResult.stcChanged.cAll;
    UI_InitProgressBar();

#ifdef _WINDOWS
    if (1 == SendMessage(GetDlgItem(hWnd, IDC_RADIO1), BM_GETCHECK, (WPARAM)0, (LPARAM)0)) {
#endif
        fAsHTML = FALSE;
        lpszExtension = TEXT(".txt");
#ifdef _WINDOWS
    }
    else {
        fAsHTML = TRUE;
        lpszExtension = TEXT(".htm");
    }
#endif

    lpszDestFileName = MYALLOC0(EXTDIRLEN * sizeof(TCHAR));
    lpszBuffer = MYALLOC0(nBufferSize * sizeof(TCHAR)); // nBufferSize must > commentlength + 10 .txt 0000
#ifdef _WINDOWS
    GetDlgItemText(hWnd, IDC_EDITCOMMENT, lpszBuffer, COMMENTLENGTH);  // length incl. NULL character
    GetDlgItemText(hWnd, IDC_EDITPATH, lpszOutputPath, MAX_PATH);  // length incl. NULL character
#endif

    cchString = _tcslen(lpszOutputPath);

    _tcscpy_s(lpszDestFileName, EXTDIRLEN, lpszOutputPath);
    if ((0 < cchString) && ((TCHAR)'\\' != lpszOutputPath[cchString - 1])) {
        _tcscat_s(lpszDestFileName, EXTDIRLEN, TEXT("\\"));
    }

    if (ReplaceInvalidFileNameChars(lpszBuffer)) {
        _tcscat_s(lpszDestFileName, EXTDIRLEN, lpszBuffer);
    }
    else {
        _tcscat_s(lpszDestFileName, EXTDIRLEN, lpszResultFileBaseName);
    }

    cchString = _tcslen(lpszDestFileName);
    _tcscat_s(lpszDestFileName, EXTDIRLEN, lpszExtension);
    hFile = CreateFile(lpszDestFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
    if (INVALID_HANDLE_VALUE == hFile) {
        DWORD filetail;

        for (filetail = 1; MAXAMOUNTOFFILE > filetail; filetail++) {
            _sntprintf_s(lpszDestFileName + cchString, EXTDIRLEN - cchString + 1, 6, TEXT("_%04u\0"), filetail);
            //*(lpszDestFileName+cchString + 5) = 0x00;
            _tcscpy_s(lpszDestFileName + cchString + 5, EXTDIRLEN - cchString - (5 + 1), lpszExtension);

            hFile = CreateFile(lpszDestFileName, GENERIC_READ | GENERIC_WRITE, FILE_SHARE_READ | FILE_SHARE_WRITE, NULL, CREATE_NEW, FILE_ATTRIBUTE_NORMAL, NULL);
            if (INVALID_HANDLE_VALUE == hFile) {
                if (ERROR_FILE_EXISTS == GetLastError()) {  // My God! I use stupid ERROR_ALREADY_EXISTS first!!
                    continue;
                }
                else {
                    ErrMsg(asLangTexts[iszTextErrorCreateFile].lpszText);
                    return FALSE;
                }
            }
            else {
                break;
            }
        }
        if (filetail >= MAXAMOUNTOFFILE) {
            ErrMsg(asLangTexts[iszTextErrorCreateFile].lpszText);
            return FALSE;
        }
    }

    if (fAsHTML) {
        WriteHTMLBegin();
    }
    else {
        WriteFile(hFile, lpszProgramName, (DWORD)(_tcslen(lpszProgramName) * sizeof(TCHAR)), &NBW, NULL);
        WriteFile(hFile, lpszCRLF, (DWORD)(_tcslen(lpszCRLF) * sizeof(TCHAR)), &NBW, NULL);
    }

    //_asm int 3;
#ifdef _WINDOWS
    GetDlgItemText(hWnd, IDC_EDITCOMMENT, lpszBuffer, COMMENTLENGTH);  // length incl. NULL character
#endif
    WriteTitle(asLangTexts[iszTextComments].lpszText, lpszBuffer, fAsHTML);

    _sntprintf_s(lpszBuffer, nBufferSize, nBufferSize, TEXT("%04d-%02d-%02d %02d:%02d:%02d, %04d-%02d-%02d %02d:%02d:%02d\0"),
        CompareResult.lpShot1->systemtime.wYear, CompareResult.lpShot1->systemtime.wMonth, CompareResult.lpShot1->systemtime.wDay,
        CompareResult.lpShot1->systemtime.wHour, CompareResult.lpShot1->systemtime.wMinute, CompareResult.lpShot1->systemtime.wSecond,
        CompareResult.lpShot2->systemtime.wYear, CompareResult.lpShot2->systemtime.wMonth, CompareResult.lpShot2->systemtime.wDay,
        CompareResult.lpShot2->systemtime.wHour, CompareResult.lpShot2->systemtime.wMinute, CompareResult.lpShot2->systemtime.wSecond);
    lpszBuffer[nBufferSize - 1] = (TCHAR)'\0'; // saftey NULL char

    WriteTitle(asLangTexts[iszTextDateTime].lpszText, lpszBuffer, fAsHTML);

    lpszBuffer[0] = (TCHAR)'\0';
    if (NULL != CompareResult.lpShot1->lpszComputerName) {
        _tcscpy_s(lpszBuffer, nBufferSize + 1, CompareResult.lpShot1->lpszComputerName);
    }
    _tcscat_s(lpszBuffer, nBufferSize, TEXT(", "));
    if (NULL != CompareResult.lpShot2->lpszComputerName) {
        _tcscat_s(lpszBuffer, nBufferSize + 1, CompareResult.lpShot2->lpszComputerName);
    }
    WriteTitle(asLangTexts[iszTextComputer].lpszText, lpszBuffer, fAsHTML);

    lpszBuffer[0] = (TCHAR)'\0';
    if (NULL != CompareResult.lpShot1->lpszUserName) {
        _tcscpy_s(lpszBuffer, nBufferSize + 1, CompareResult.lpShot1->lpszUserName);
    }
    _tcscat_s(lpszBuffer, nBufferSize + 1, TEXT(", "));
    if (NULL != CompareResult.lpShot2->lpszUserName) {
        _tcscat_s(lpszBuffer, nBufferSize + 1, CompareResult.lpShot2->lpszUserName);
    }
    WriteTitle(asLangTexts[iszTextUsername].lpszText, lpszBuffer, fAsHTML);

    MYFREE(lpszBuffer);

    // Write keydel part
    if (0 != CompareResult.stcDeleted.cKeys) {
        WriteTableHead(asLangTexts[iszTextKeyDel].lpszText, CompareResult.stcDeleted.cKeys, fAsHTML);
        WritePart(KEYDEL, CompareResult.stCRHeads.lpCRKeyDeleted, fAsHTML, TRUE);
    }
    // Write keyadd part
    if (0 != CompareResult.stcAdded.cKeys) {
        WriteTableHead(asLangTexts[iszTextKeyAdd].lpszText, CompareResult.stcAdded.cKeys, fAsHTML);
        WritePart(KEYADD, CompareResult.stCRHeads.lpCRKeyAdded, fAsHTML, TRUE);
    }
    // Write valdel part
    if (0 != CompareResult.stcDeleted.cValues) {
        WriteTableHead(asLangTexts[iszTextValDel].lpszText, CompareResult.stcDeleted.cValues, fAsHTML);
        WritePart(VALDEL, CompareResult.stCRHeads.lpCRValDeleted, fAsHTML, TRUE);
    }
    // Write valadd part
    if (0 != CompareResult.stcAdded.cValues) {
        WriteTableHead(asLangTexts[iszTextValAdd].lpszText, CompareResult.stcAdded.cValues, fAsHTML);
        WritePart(VALADD, CompareResult.stCRHeads.lpCRValAdded, fAsHTML, TRUE);
    }
    // Write valmodi part
    if (0 != CompareResult.stcModified.cValues) {
        WriteTableHead(asLangTexts[iszTextValModi].lpszText, CompareResult.stcModified.cValues, fAsHTML);
        WritePart(VALMODI, CompareResult.stCRHeads.lpCRValModified, fAsHTML, TRUE);
    }
    // Write directory del part
    if (0 != CompareResult.stcDeleted.cDirs) {
        WriteTableHead(asLangTexts[iszTextDirDel].lpszText, CompareResult.stcDeleted.cDirs, fAsHTML);
        WritePart(DIRDEL, CompareResult.stCRHeads.lpCRDirDeleted, fAsHTML, TRUE);
    }
    // Write directory add part
    if (0 != CompareResult.stcAdded.cDirs) {
        WriteTableHead(asLangTexts[iszTextDirAdd].lpszText, CompareResult.stcAdded.cDirs, fAsHTML);
        WritePart(DIRADD, CompareResult.stCRHeads.lpCRDirAdded, fAsHTML, TRUE);
    }
    // Write directory modi part
    if (0 != CompareResult.stcModified.cDirs) {
        WriteTableHead(asLangTexts[iszTextDirModi].lpszText, CompareResult.stcModified.cDirs, fAsHTML);
        WritePart(DIRMODI, CompareResult.stCRHeads.lpCRDirModified, fAsHTML, TRUE);
    }
    // Write file del part
    if (0 != CompareResult.stcDeleted.cFiles) {
        WriteTableHead(asLangTexts[iszTextFileDel].lpszText, CompareResult.stcDeleted.cFiles, fAsHTML);
        WritePart(FILEDEL, CompareResult.stCRHeads.lpCRFileDeleted, fAsHTML, TRUE);
    }
    // Write file add part
    if (0 != CompareResult.stcAdded.cFiles) {
        WriteTableHead(asLangTexts[iszTextFileAdd].lpszText, CompareResult.stcAdded.cFiles, fAsHTML);
        WritePart(FILEADD, CompareResult.stCRHeads.lpCRFileAdded, fAsHTML, TRUE);
    }
    // Write file modi part
    if (0 != CompareResult.stcModified.cFiles) {
        WriteTableHead(asLangTexts[iszTextFileModi].lpszText, CompareResult.stcModified.cFiles, fAsHTML);
        WritePart(FILEMODI, CompareResult.stCRHeads.lpCRFileModified, fAsHTML, TRUE);
    }

    if (fAsHTML) {
        WriteHTML_BR();
    }
    WriteTableHead(asLangTexts[iszTextTotal].lpszText, CompareResult.stcChanged.cAll, fAsHTML);
    if (fAsHTML) {
        WriteHTMLEnd();
    }

    // Close file
    CloseHandle(hFile);

#ifdef _WINDOWS
    if (32 >= (size_t)ShellExecute(hWnd, TEXT("open"), lpszDestFileName, NULL, NULL, SW_SHOW)) {
        ErrMsg(asLangTexts[iszTextErrorExecViewer].lpszText);
    }
#endif
    MYFREE(lpszDestFileName);

    UI_ShowHideProgressBar(SW_HIDE);

    return TRUE;
}


// ----------------------------------------------------------------------
// Clear comparison match flags of registry keys and values
// ----------------------------------------------------------------------
VOID ClearRegKeyMatchFlags(LPKEYCONTENT lpKC)
{
    LPVALUECONTENT lpVC;

    for (; NULL != lpKC; lpKC = lpKC->lpBrotherKC) {
        lpKC->fKeyMatch = NOMATCH;
        for (lpVC = lpKC->lpFirstVC; NULL != lpVC; lpVC = lpVC->lpBrotherVC) {
            lpVC->fValueMatch = NOMATCH;
        }
        ClearRegKeyMatchFlags(lpKC->lpFirstSubKC);
    }
}


// ----------------------------------------------------------------------
// Free all registry values
// ----------------------------------------------------------------------
VOID FreeAllValueContents(LPVALUECONTENT lpVC)
{
    LPVALUECONTENT lpBrotherVC;

    for (; NULL != lpVC; lpVC = lpBrotherVC) {
        // Save pointer in local variable
        lpBrotherVC = lpVC->lpBrotherVC;

        // Increase count
        cCurrent++;

        // Free value name
        if (NULL != lpVC->lpszValueName) {
            MYFREE(lpVC->lpszValueName);
        }

        // Free value data
        if (NULL != lpVC->lpValueData) {
            MYFREE(lpVC->lpValueData);
        }

        // Free entry itself
        MYFREE(lpVC);
    }
}


// ----------------------------------------------------------------------
// Free all registry keys and values
// ----------------------------------------------------------------------
VOID FreeAllKeyContents(LPKEYCONTENT lpKC)
{
    LPKEYCONTENT lpBrotherKC;

    for (; NULL != lpKC; lpKC = lpBrotherKC) {
        // Save pointer in local variable
        lpBrotherKC = lpKC->lpBrotherKC;

        // Increase count
        cCurrent++;

        // Free key name
        if (NULL != lpKC->lpszKeyName) {
            if ((NULL != lpKC->lpFatherKC)  // only the top KC can have HKLM/HKU, so ignore the sub KCs
                || ((lpKC->lpszKeyName != lpszHKLMShort)
                    && (lpKC->lpszKeyName != lpszHKLMLong)
                    && (lpKC->lpszKeyName != lpszHKUShort)
                    && (lpKC->lpszKeyName != lpszHKULong))) {
                MYFREE(lpKC->lpszKeyName);
            }
        }

        // If the entry has values, then do a call for the first value
        if (NULL != lpKC->lpFirstVC) {
            FreeAllValueContents(lpKC->lpFirstVC);
        }

        // Update progress bar display
        if (0 != cEnd) {
            nCurrentTime = GetTickCount();
            if (REFRESHINTERVAL < (nCurrentTime - nLastTime)) {
                UI_UpdateProgressBar();
            }
        }

        // If the entry has childs, then do a recursive call for the first child
        if (NULL != lpKC->lpFirstSubKC) {
            FreeAllKeyContents(lpKC->lpFirstSubKC);
        }

        // Free entry itself
        MYFREE(lpKC);
    }
}


// ----------------------------------------------------------------------
// Free shot completely and initialize
// ----------------------------------------------------------------------
VOID FreeShot(LPREGSHOT lpShot)
{
    if (NULL != lpShot->lpszComputerName) {
        MYFREE(lpShot->lpszComputerName);
    }

    if (NULL != lpShot->lpszUserName) {
        MYFREE(lpShot->lpszUserName);
    }

    if (NULL != lpShot->lpHKLM) {
        FreeAllKeyContents(lpShot->lpHKLM);
    }

    if (NULL != lpShot->lpHKU) {
        FreeAllKeyContents(lpShot->lpHKU);
    }

    if (NULL != lpShot->lpHF) {
        FreeAllHeadFiles(lpShot->lpHF);
    }

    if (NULL != lpShot->lpUsnSnapshot) {
        UsnSnapshotFree(lpShot->lpUsnSnapshot);
    }

    ZeroMemory(lpShot, sizeof(REGSHOT));
}


// ----------------------------------------------------------------------
// Get registry snap shot
// ----------------------------------------------------------------------
static LONG EnumerateSnapshotValue(HKEY key, DWORD index, DWORD* nameLength,
    DWORD* type, DWORD* dataLength, DWORD nameCapacity, DWORD dataCapacity)
{
    DWORD retry;
    LONG error;

    for (retry = 0; ; ++retry) {
        *nameLength = nameCapacity;
        *dataLength = dataCapacity;
        error = RegEnumValue(key, index, lpStringBuffer, nameLength, NULL,
            type, lpDataBuffer, dataLength);
        if (error != ERROR_MORE_DATA || retry == 8)
            return error;
        if (nameCapacity > MAXDWORD / (2 * sizeof(TCHAR)) || dataCapacity > MAXDWORD / 2)
            return ERROR_NOT_ENOUGH_MEMORY;
        nameCapacity *= 2;
        dataCapacity = *dataLength > dataCapacity ? *dataLength : dataCapacity * 2;
        nStringBufferSize = AdjustBuffer((LPVOID*)&lpStringBuffer, nStringBufferSize,
            nameCapacity * sizeof(TCHAR), REGSHOT_BUFFER_BLOCK_BYTES);
        nDataBufferSize = AdjustBuffer((LPVOID*)&lpDataBuffer, nDataBufferSize,
            dataCapacity, REGSHOT_BUFFER_BLOCK_BYTES);
        if (lpStringBuffer == NULL || lpDataBuffer == NULL)
            return ERROR_NOT_ENOUGH_MEMORY;
    }
}

static LPKEYCONTENT CreateSnapshotKey(LPREGSHOT shot, LPTSTR name, LPKEYCONTENT father, LPKEYCONTENT* caller)
{
    LPKEYCONTENT key = MYALLOC0(sizeof(*key));
    LPTSTR fullName;

    if (key == NULL) {
        shot->fIncomplete = TRUE;
        OutputDebugString(TEXT("Registry snapshot: key allocation failed.\n"));
        if (father != NULL)
            MYFREE(name);
        return NULL;
    }
    key->lpFatherKC = father;
    key->lpszKeyName = name;
    key->cchKeyName = _tcslen(name);
    if (lprgszRegSkipStrings[0] != NULL) {
        if (IsInSkipList(name, lprgszRegSkipStrings)) {
            FreeAllKeyContents(key);
            return NULL;
        }
        fullName = GetWholeKeyName(key, FALSE);
        if (fullName == NULL) {
            shot->fIncomplete = TRUE;
            OutputDebugString(TEXT("Registry snapshot: key path allocation failed.\n"));
            FreeAllKeyContents(key);
            return NULL;
        }
        if (IsInSkipList(fullName, lprgszRegSkipStrings)) {
            MYFREE(fullName);
            FreeAllKeyContents(key);
            return NULL;
        }
        MYFREE(fullName);
    }
    if (caller != NULL)
        *caller = key;
    ++shot->stCounts.cKeys;
    return key;
}

static VOID MarkRegistryScanError(LPREGSHOT shot, LPKEYCONTENT key, DWORD error)
{
    TCHAR message[1024];
    LPTSTR path = GetWholeKeyName(key, FALSE);

    if (key->nScanError == 0)
        ++shot->cSkippedRegKeys;
    key->nScanError = error;
    _sntprintf_s(message, _countof(message), _TRUNCATE,
        TEXT("Registry snapshot: contents unavailable for %s (error %lu).\n"),
        path != NULL ? path : key->lpszKeyName, error);
    OutputDebugString(message);
    if (path != NULL)
        MYFREE(path);
}

static LONG EnumerateSnapshotKey(HKEY key, DWORD index, DWORD* nameLength)
{
    DWORD retry;
    LONG error;

    for (retry = 0; ; ++retry) {
        *nameLength = (DWORD)(nStringBufferSize / sizeof(TCHAR));
        error = RegEnumKeyEx(key, index, lpStringBuffer, nameLength, NULL, NULL, NULL, NULL);
        if (error != ERROR_MORE_DATA || retry == 8)
            return error;
        if (nStringBufferSize > MAXDWORD / 2)
            return ERROR_NOT_ENOUGH_MEMORY;
        nStringBufferSize = AdjustBuffer((LPVOID*)&lpStringBuffer, nStringBufferSize,
            nStringBufferSize * 2, REGSHOT_BUFFER_BLOCK_BYTES);
        if (lpStringBuffer == NULL)
            return ERROR_NOT_ENOUGH_MEMORY;
    }
}

LPKEYCONTENT GetRegistrySnap(LPREGSHOT lpShot, HKEY hRegKey, LPTSTR lpszRegKeyName, LPKEYCONTENT lpFatherKC, LPKEYCONTENT* lplpCaller)
{
    LPKEYCONTENT lpKC;
    DWORD cSubKeys;
    DWORD cchMaxSubKeyName;

    // Process registry key itself, then key values with data, then sub keys (see msdn.microsoft.com/en-us/library/windows/desktop/ms724256.aspx)

    // Extra local block to reduce stack usage due to recursive calls
    {
        LPTSTR lpszFullName;
        DWORD cValues;
        DWORD cchMaxValueName;
        DWORD cbMaxValueData;

        lpKC = CreateSnapshotKey(lpShot, lpszRegKeyName, lpFatherKC, lplpCaller);
        if (lpKC == NULL)
            return NULL;

        // Examine key for values and sub keys, get counts and also maximum lengths of names plus value data
        nErrNo = RegQueryInfoKey(
            hRegKey,
            NULL,
            NULL,
            NULL,
            &cSubKeys,
            &cchMaxSubKeyName,  // in TCHARs *not* incl. NULL char
            NULL,
            &cValues,
            &cchMaxValueName,   // in TCHARs *not* incl. NULL char
            &cbMaxValueData,
            NULL,
            NULL
        );
        if (ERROR_SUCCESS != nErrNo) {
            MarkRegistryScanError(lpShot, lpKC, nErrNo);
            return lpKC;
        }

        // Copy the registry values of the current key
        if (0 < cValues) {
            LPVALUECONTENT lpVC;
            LPVALUECONTENT* lplpVCPrev;
            DWORD i;
            DWORD cchValueName;
            DWORD nValueType;
            DWORD cbValueData;
#ifdef DEBUGLOG
            LPTSTR lpszDebugMsg;
#endif

            // Account for NULL char
            cchMaxValueName++;

            // Get buffer for maximum value name length
            nSourceSize = cchMaxValueName * sizeof(TCHAR);
            nStringBufferSize = AdjustBuffer(&lpStringBuffer, nStringBufferSize, nSourceSize, REGSHOT_BUFFER_BLOCK_BYTES);

            // Get buffer for maximum value data length
            nSourceSize = cbMaxValueData != 0 ? cbMaxValueData : 1;
            nDataBufferSize = AdjustBuffer(&lpDataBuffer, nDataBufferSize, nSourceSize, REGSHOT_BUFFER_BLOCK_BYTES);
            if (lpStringBuffer == NULL || lpDataBuffer == NULL) {
                lpShot->fIncomplete = TRUE;
                OutputDebugString(TEXT("Registry snapshot: value buffers could not be allocated.\n"));
                return lpKC;
            }

            // Get registry key values
            lplpVCPrev = &lpKC->lpFirstVC;
            for (i = 0; ; i++) {
                nErrNo = EnumerateSnapshotValue(hRegKey, i, &cchValueName,
                    &nValueType, &cbValueData, cchMaxValueName,
                    cbMaxValueData != 0 ? cbMaxValueData : 1);
                if (ERROR_NO_MORE_ITEMS == nErrNo) {
                    break;
                }
                if (ERROR_SUCCESS != nErrNo) {
                    lpShot->fIncomplete = TRUE;
                    OutputDebugString(TEXT("Registry snapshot: value enumeration failed.\n"));
                    if (ERROR_NOT_ENOUGH_MEMORY == nErrNo)
                        break;
                    continue;
                }
                lpStringBuffer[cchValueName] = (TCHAR)'\0';  // safety NULL char

#ifdef DEBUGLOG
                DebugLog(lpszDebugTryToGetValueLog, TEXT("trying: "), FALSE);
                DebugLog(lpszDebugTryToGetValueLog, lpStringBuffer, TRUE);
#endif

                // Create new value content
                // put in a separate var for later use
                lpVC = MYALLOC0(sizeof(VALUECONTENT));

                // Set father key of current value to current key
                lpVC->lpFatherKC = lpKC;

                // Copy value name
                if (0 < cchValueName) {
                    lpVC->lpszValueName = MYALLOC((cchValueName + 1) * sizeof(TCHAR));
                    _tcscpy_s(lpVC->lpszValueName, cchValueName + 1, lpStringBuffer);
                    lpVC->cchValueName = _tcslen(lpVC->lpszValueName);
                }
                
                // Check if value is to be excluded
                if (NULL != lprgszRegSkipStrings[0]) {  // only if there is something to exclude
                    if ((NULL != lpVC->lpszValueName) && (IsInSkipList(lpVC->lpszValueName, lprgszRegSkipStrings))) {
                        FreeAllValueContents(lpVC);
                        continue;  // ignore this entry and continue with next brother value
                    }

                    lpszFullName = GetWholeValueName(lpVC, FALSE);
                    if (IsInSkipList(lpszFullName, lprgszRegSkipStrings)) {
                        MYFREE(lpszFullName);
                        FreeAllValueContents(lpVC);
                        continue;  // ignore this entry and continue with next brother value
                    }
                    MYFREE(lpszFullName);
                }

                // Copy pointer to current value into previous value's next value pointer
                if (NULL != lplpVCPrev) {
                    *lplpVCPrev = lpVC;
                }

                // Increase value count
                lpShot->stCounts.cValues++;

                // Copy value meta data
                lpVC->nTypeCode = nValueType;
                lpVC->cbData = cbValueData;

                // Copy value data
                if (0 < cbValueData) {  // otherwise leave it NULL
                    lpVC->lpValueData = MYALLOC(cbValueData);
                    CopyMemory(lpVC->lpValueData, lpDataBuffer, cbValueData);
                }

#ifdef DEBUGLOG
                lpszDebugMsg = MYALLOC0(REGSHOT_DEBUG_MESSAGE_LENGTH * sizeof(TCHAR));
                _sntprintf(lpszDebugMsg, REGSHOT_DEBUG_MESSAGE_LENGTH, TEXT("LGVN:%08d LGVD:%08d VN:%08d VD:%08d\0"), cchMaxValueName, cbMaxValueData, cchValueName, cbValueData);
                lpszDebugMsg[REGSHOT_DEBUG_MESSAGE_LENGTH - 1] = (TCHAR)'\0';  // safety NULL char
                DebugLog(lpszDebugValueNameDataLog, lpszDebugMsg, TRUE);
                MYFREE(lpszDebugMsg);

                lpszDebugMsg = GetWholeValueName(lpVC, FALSE);
                DebugLog(lpszDebugValueNameDataLog, lpszDebugMsg, FALSE);
                MYFREE(lpszDebugMsg);

                lpszDebugMsg = GetWholeValueData(lpVC, FALSE);
                DebugLog(lpszDebugValueNameDataLog, lpszDebugMsg, TRUE);
                MYFREE(lpszDebugMsg);
#endif

                // Set "lpBrotherVC" pointer for storing the next brother's pointer
                lplpVCPrev = &lpVC->lpBrotherVC;
            }
        }
    }  // End of extra local block

    // Update counters display
    nCurrentTime = GetTickCount();
    if (REFRESHINTERVAL < (nCurrentTime - nLastTime)) {
        UI_UpdateCounters(asLangTexts[iszTextKey].lpszText, asLangTexts[iszTextValue].lpszText, lpShot->stCounts.cKeys, lpShot->stCounts.cValues);
    }

    // Process sub keys
    if (0 < cSubKeys) {
        LPKEYCONTENT lpKCSub;
        LPKEYCONTENT* lplpKCPrev;
        DWORD i;
        LPTSTR lpszRegSubKeyName;
        HKEY hRegSubKey;

        // Account for NULL char
        if (0 < cchMaxSubKeyName) {
            cchMaxSubKeyName++;
        }

        // Get buffer for maximum sub key name length
        nSourceSize = cchMaxSubKeyName * sizeof(TCHAR);
        nStringBufferSize = AdjustBuffer(&lpStringBuffer, nStringBufferSize, nSourceSize, REGSHOT_BUFFER_BLOCK_BYTES);
        if (lpStringBuffer == NULL) {
            lpShot->fIncomplete = TRUE;
            OutputDebugString(TEXT("Registry snapshot: subkey buffer allocation failed.\n"));
            return lpKC;
        }

        // Get registry sub keys
        lplpKCPrev = &lpKC->lpFirstSubKC;
        for (i = 0; ; i++) {
            // Extra local block to reduce stack usage due to recursive calls
            {
                DWORD cchSubKeyName;
#ifdef DEBUGLOG
                LPTSTR lpszDebugMsg;
#endif

                // Enumerate sub key
                nErrNo = EnumerateSnapshotKey(hRegKey, i, &cchSubKeyName);
                if (ERROR_NO_MORE_ITEMS == nErrNo) {
                    break;
                }
                if (ERROR_SUCCESS != nErrNo) {
                    if (nErrNo == ERROR_NOT_ENOUGH_MEMORY || nErrNo == ERROR_MORE_DATA) {
                        lpShot->fIncomplete = TRUE;
                        OutputDebugString(TEXT("Registry snapshot: subkey enumeration retries failed.\n"));
                    }
                    else {
                        MarkRegistryScanError(lpShot, lpKC, nErrNo);
                    }
                    break;
                }
                lpStringBuffer[cchSubKeyName] = (TCHAR)'\0';  // safety NULL char

                // Copy sub key name
                lpszRegSubKeyName = NULL;
                if (0 < cchSubKeyName) {
                    lpszRegSubKeyName = MYALLOC0((cchSubKeyName + 1) * sizeof(TCHAR));
                    if (lpszRegSubKeyName == NULL) {
                        lpShot->fIncomplete = TRUE;
                        OutputDebugString(TEXT("Registry snapshot: subkey name allocation failed.\n"));
                        break;
                    }
                    _tcscpy_s(lpszRegSubKeyName, cchSubKeyName + 1, lpStringBuffer);
                }

#ifdef DEBUGLOG
                lpszDebugMsg = MYALLOC0(REGSHOT_DEBUG_MESSAGE_LENGTH * sizeof(TCHAR));
                _sntprintf(lpszDebugMsg, REGSHOT_DEBUG_MESSAGE_LENGTH, TEXT("LGKN:%08d KN:%08d\0"), cchMaxSubKeyName, cchSubKeyName);
                lpszDebugMsg[REGSHOT_DEBUG_MESSAGE_LENGTH - 1] = (TCHAR)'\0';  // safety NULL char
                DebugLog(lpszDebugKeyLog, lpszDebugMsg, TRUE);
                MYFREE(lpszDebugMsg);

                lpszDebugMsg = GetWholeKeyName(lpKC, FALSE);
                DebugLog(lpszDebugKeyLog, lpszDebugMsg, FALSE);
                MYFREE(lpszDebugMsg);

                DebugLog(lpszDebugKeyLog, TEXT("\\"), FALSE);
                DebugLog(lpszDebugKeyLog, lpszRegSubKeyName, TRUE);
#endif
            }  // End of extra local block

            nErrNo = RegOpenKeyEx(hRegKey, lpszRegSubKeyName, 0, KEY_QUERY_VALUE | KEY_ENUMERATE_SUB_KEYS, &hRegSubKey);
            if (ERROR_SUCCESS != nErrNo) {
                LONG openError = nErrNo;
                lpKCSub = CreateSnapshotKey(lpShot, lpszRegSubKeyName, lpKC, lplpKCPrev);
                if (lpKCSub != NULL)
                    MarkRegistryScanError(lpShot, lpKCSub, openError);
            }
            else {
                lpKCSub = GetRegistrySnap(lpShot, hRegSubKey, lpszRegSubKeyName, lpKC, lplpKCPrev);
                RegCloseKey(hRegSubKey);
            }
            if (lpShot->fIncomplete)
                break;

            // Set "lpBrotherKC" pointer for storing the next brother's pointer
            if (NULL != lpKCSub) {
                lplpKCPrev = &lpKCSub->lpBrotherKC;
            }
        }
    }

    return lpKC;
}


// ----------------------------------------------------------------------
// Shot Engine
// ----------------------------------------------------------------------
VOID Shot(LPREGSHOT lpShot)
{
    DWORD cchString;

#ifdef _CONSOLE
    _tprintf(_T("Snapshot - BEGIN\n"));
#endif
    // Clear shot
    cEnd = 0;
    FreeShot(lpShot);

    // Setup GUI for shot...
    UI_InitCounters();

    // New temporary buffers
    lpStringBuffer = NULL;
    lpDataBuffer = NULL;

    // Set computer name
    lpShot->lpszComputerName = MYALLOC0((MAX_COMPUTERNAME_LENGTH + 1) * sizeof(TCHAR));
    cchString = MAX_COMPUTERNAME_LENGTH + 1;
    GetComputerName(lpShot->lpszComputerName, &cchString);   // in TCHARs; in *including* and out *excluding* NULL char

    // Set user name
    lpShot->lpszUserName = MYALLOC0((UNLEN + 1) * sizeof(TCHAR));
    cchString = UNLEN + 1;
    GetUserName(lpShot->lpszUserName, &cchString);   // in TCHARs; in and out including NULL char
    
    // Set current system time
    GetSystemTime(&lpShot->systemtime);

#ifdef _CONSOLE
    _tprintf(_T("\tGetRegistrySnap HKEY_LOCAL_MACHINE...\n"));
#endif
    // Take HKLM registry shot
    GetRegistrySnap(lpShot, HKEY_LOCAL_MACHINE, lpszHKLMShort, NULL, &lpShot->lpHKLM);
#ifdef _CONSOLE
    UI_ShowHideCounters(SW_HIDE);
#endif

    // Update counters display (reg keys/values final)
    nCurrentTime = GetTickCount();
    UI_UpdateCounters(asLangTexts[iszTextKey].lpszText, asLangTexts[iszTextValue].lpszText, lpShot->stCounts.cKeys, lpShot->stCounts.cValues);

#ifdef _CONSOLE
    UI_ShowHideCounters(SW_HIDE);
    _tprintf(_T("\tGetRegistrySnap HKEY_USERS...\n"));
#endif
    // Take HKU registry shot
    GetRegistrySnap(lpShot, HKEY_USERS, lpszHKUShort, NULL, &lpShot->lpHKU);
#ifdef _CONSOLE
    UI_ShowHideCounters(SW_HIDE);
#endif

    // Update counters display (reg keys/values final)
    nCurrentTime = GetTickCount();
    UI_UpdateCounters(asLangTexts[iszTextKey].lpszText, asLangTexts[iszTextValue].lpszText, lpShot->stCounts.cKeys, lpShot->stCounts.cValues);
#ifdef _CONSOLE
    UI_ShowHideCounters(SW_HIDE);
    _tprintf(_T("\tFileShot...\n"));
#endif

    // Take file shot
#ifdef _WINDOWS
    if (BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_CHECKDIR), BM_GETCHECK, (WPARAM)0, (LPARAM)0)
        || BST_CHECKED == SendMessage(GetDlgItem(hWnd, IDC_CHECKUSN), BM_GETCHECK, (WPARAM)0, (LPARAM)0)) {
#endif
        FileShot(lpShot);

        // Update counters display (dirs/files final)
        nCurrentTime = GetTickCount();
        UI_UpdateCounters(asLangTexts[iszTextDir].lpszText, asLangTexts[iszTextFile].lpszText, lpShot->stCounts.cDirs, lpShot->stCounts.cFiles);
#ifdef _CONSOLE
        UI_ShowHideCounters(SW_HIDE);
#endif
#ifdef _WINDOWS
    }
#endif

    // Get total count of all items
    lpShot->stCounts.cAll = lpShot->stCounts.cKeys
        + lpShot->stCounts.cValues
        + lpShot->stCounts.cDirs
        + lpShot->stCounts.cFiles;
#ifdef _CONSOLE
    _tprintf(_T("\tRESULT : RegKeys=%u ; RegEntries=%u ; Dirs=%u ; Files=%u ; Total=%u\n")
        , lpShot->stCounts.cKeys
        , lpShot->stCounts.cValues
        , lpShot->stCounts.cDirs
        , lpShot->stCounts.cFiles
        , lpShot->stCounts.cAll
    );
#endif

    if (lpShot->fIncomplete) {
        FreeShot(lpShot);
        ErrMsg(TEXT("Snapshot was incomplete and has been discarded. Check access permissions and retry."));
        UI_ShowHideCounters(SW_HIDE);
        goto cleanupShotBuffers;
    }

    // Set flags
    lpShot->fFilled = TRUE;
    lpShot->fLoaded = FALSE;

    UI_ShowHideCounters(SW_HIDE);
    if (lpShot->cSkippedRegKeys != 0) {
        TCHAR warning[384];

        _sntprintf_s(warning, _countof(warning), _TRUNCATE,
            asLangTexts[iszTextRegistryScanWarning].lpszText,
            lpShot->cSkippedRegKeys);
#ifdef _WINDOWS
        MessageBox(hWnd, warning, asLangTexts[iszTextWarning].lpszText, MB_OK | MB_ICONWARNING);
#else
        _tprintf(TEXT("%s\n"), warning);
#endif
    }
    if (lpShot->cSkippedDirs != 0) {
        TCHAR warning[384];

        _sntprintf_s(warning, _countof(warning), _TRUNCATE,
            asLangTexts[iszTextScanWarning].lpszText,
            lpShot->cSkippedDirs);
#ifdef _WINDOWS
        MessageBox(hWnd, warning, asLangTexts[iszTextWarning].lpszText, MB_OK | MB_ICONWARNING);
#else
        _tprintf(TEXT("%s\n"), warning);
#endif
    }

cleanupShotBuffers:
    if (NULL != lpStringBuffer) {
        MYFREE(lpStringBuffer);
        lpStringBuffer = NULL;
    }
    if (NULL != lpDataBuffer) {
        MYFREE(lpDataBuffer);
        lpDataBuffer = NULL;
    }
#ifdef _CONSOLE
    _tprintf(_T("Snapshot - END\n"));
#endif
}


// ----------------------------------------------------------------------
// Write file buffer content to file with a single write
// ----------------------------------------------------------------------
VOID EmptyFileBuffer(VOID)
{
    if ((NULL != lpFileBuffer) && (0 < fileextradata.ofsFBuffer)) {
        if (!WriteFile(hFileWholeReg, lpFileBuffer, fileextradata.ofsFBuffer, &NBW, NULL) || NBW != fileextradata.ofsFBuffer) {
            fHiveWriteFailed = TRUE;
        }
        fileextradata.ofsFBFile += fileextradata.ofsFBuffer;
        fileextradata.ofsFBuffer = 0;
    }
}


// ----------------------------------------------------------------------
// Write file content to file buffer to speed up saving onto network drives
// as a lot of SetFilePointer() calls will extremely decrease save speed
// ----------------------------------------------------------------------
VOID WriteFileBuffer(long ofsFile, LPCVOID lpData, DWORD cbData)
{
    DWORD ofsFileDW;
    long  ofsFileCurrent;

    if (0 >= cbData) {  // Ignore, but still Aaarrrggghhh!!!
        return;
    }

    ofsFileCurrent = (long)fileextradata.ofsFBFile + (long)fileextradata.ofsFBuffer;

    if (0 > ofsFile) {  // special case: negative value means append
        ofsFile = ofsFileCurrent;
    }
    else {
        // Error case: Writing only allowed before or at current file offset (replace or append)
        assert(ofsFileCurrent >= ofsFile);
    }

    ofsFileDW = ofsFile;

    if ((long)fileextradata.ofsFBFile > ofsFile) {
        // Error case: Writing before buffer only allowed if data is not reaching into the buffer / no buffer: behind current file end
        assert((ofsFile + (long)cbData) <= (long)fileextradata.ofsFBFile);

        if ((INVALID_SET_FILE_POINTER == SetFilePointer(hFileWholeReg, ofsFileDW, NULL, FILE_BEGIN))
            || !WriteFile(hFileWholeReg, lpData, cbData, &NBW, NULL) || NBW != cbData
            || (INVALID_SET_FILE_POINTER == SetFilePointer(hFileWholeReg, fileextradata.ofsFBFile, NULL, FILE_BEGIN))) {
            fHiveWriteFailed = TRUE;
        }
        return;
    }

    if ((NULL == lpFileBuffer) && (!fileextradata.bFBStopAlloc)) {
        DWORD cbNewSize;

        cbNewSize = 1024 * 1024;  // 1 MiB
        lpFileBuffer = MYALLOC(cbNewSize);
        if (NULL == lpFileBuffer) {
            cbNewSize = 128 * 1024;  // 128 KiB
            lpFileBuffer = MYALLOC(cbNewSize);
        }
        if (NULL == lpFileBuffer) {
            cbNewSize = 10 * 1024;  // 10 KiB
            lpFileBuffer = MYALLOC(cbNewSize);
        }
        if (NULL == lpFileBuffer) {
            cbNewSize = 1024;  // 1 KiB
            lpFileBuffer = MYALLOC(cbNewSize);
        }
        if (NULL == lpFileBuffer) {
            fileextradata.bFBStopAlloc = TRUE;
        }
        else {
            fileextradata.cbFBuffer = cbNewSize;
        }
    }

    if (NULL != lpFileBuffer) {
        DWORD cbWantedSize;

        // Error case: Not appending but still writing over current buffer offset
        if (ofsFileCurrent > ofsFile) {
            assert((ofsFile + (long)cbData) <= ofsFileCurrent);
        }

        cbWantedSize = ofsFileDW - fileextradata.ofsFBFile + cbData;

        if (cbWantedSize > fileextradata.cbFBuffer) {
            EmptyFileBuffer();
            cbWantedSize = ofsFileDW - fileextradata.ofsFBFile + cbData;
        }

        if (cbWantedSize <= fileextradata.cbFBuffer) {
            ofsFileDW -= fileextradata.ofsFBFile;
            CopyMemory((lpFileBuffer + ofsFileDW), lpData, cbData);
            if (ofsFileDW == fileextradata.ofsFBuffer) {
                fileextradata.ofsFBuffer += cbData;
            }
            return;
        }
    }

    // Fallback: direct append (e.g. no buffer or buffer too small)
    if (!WriteFile(hFileWholeReg, lpData, cbData, &NBW, NULL) || NBW != cbData) {
        fHiveWriteFailed = TRUE;
    }
    fileextradata.ofsFBFile += cbData;
}


// ----------------------------------------------------------------------
// Save registry key with values to HIVE file
//
// This routine is called recursively to store the keys of the Registry tree
// Therefore temporary vars are put in a local block to reduce stack usage
// ----------------------------------------------------------------------
VOID SaveRegKeys(LPREGSHOT lpShot, LPKEYCONTENT lpKC, DWORD nFPFatherKey, DWORD nFPCaller)
{
    DWORD nFPKey;

    for (; NULL != lpKC; lpKC = lpKC->lpBrotherKC) {
        // Get current file position
        // put in a separate var for later use
        nFPKey = fileextradata.ofsFBFile + fileextradata.ofsFBuffer;

        // Write position of current reg key in caller's field
        if (0 < nFPCaller) {
            WriteFileBuffer(nFPCaller, &nFPKey, sizeof(nFPKey));
        }

        // Initialize key content

        // Set file positions of the relatives inside the tree
#ifdef _UNICODE
        sKC.ofsKeyName = 0;      // not known yet, may be defined in this call
#endif
#ifndef _UNICODE
        // Key name will always be stored behind the structure, so its position is already known
        sKC.ofsKeyName = nFPKey + sizeof(sKC);
#endif
        sKC.ofsFirstValue = 0;   // not known yet, may be re-written in this iteration
        sKC.ofsFirstSubKey = 0;  // not known yet, may be re-written by another recursive call
        sKC.ofsBrotherKey = 0;   // not known yet, may be re-written in another iteration
        sKC.ofsFatherKey = nFPFatherKey;

        // New since key content version 2
        sKC.nKeyNameLen = 0;
        sKC.nScanError = lpKC->nScanError;

        // Extra local block to reduce stack usage due to recursive calls
        {
            LPTSTR lpszKeyName;

            lpszKeyName = lpKC->lpszKeyName;

            // Determine correct key name and length plus file offset
            if (NULL != lpszKeyName) {
                sKC.nKeyNameLen = (DWORD)lpKC->cchKeyName;

                if ((fUseLongRegHead) && (0 == nFPFatherKey)) {
                    // Adopt to long HKLM/HKU
                    if (lpszHKLMShort == lpszKeyName) {
                        lpszKeyName = lpszHKLMLong;
                        sKC.nKeyNameLen = (DWORD)_tcslen(lpszKeyName);;
                    }
                    else if (lpszHKUShort == lpszKeyName) {
                        lpszKeyName = lpszHKULong;
                        sKC.nKeyNameLen = (DWORD)_tcslen(lpszKeyName);;
                    }
                }

                // Determine key name length and file offset
                if (0 < sKC.nKeyNameLen) {  // otherwise leave it all 0
                    sKC.nKeyNameLen++;  // account for NULL char
#ifdef _UNICODE
                    // Key name will always be stored behind the structure, so its position is already known
                    sKC.ofsKeyName = nFPKey + sizeof(sKC);
#endif
                }
            }

            // Increase count
            cCurrent++;

            // Write key content to file
            // Make sure that ALL fields have been initialized/set
            WriteFileBuffer(-1, &sKC, sizeof(sKC));

            // Write key name to file
            if (0 < sKC.nKeyNameLen) {
                WriteFileBuffer(-1, lpszKeyName, sKC.nKeyNameLen * sizeof(TCHAR));
#ifndef _UNICODE
            }
            else {
                // Write empty string for backward compatibility
                WriteFileBuffer(-1, lpszEmpty, 1 * sizeof(TCHAR));
#endif
            }
        }  // End of extra local block

        // Save the values of the current key
        if (NULL != lpKC->lpFirstVC) {
            LPVALUECONTENT lpVC;
            DWORD nFPValue;

            // Write all values of key
            nFPCaller = nFPKey + offsetof(SAVEKEYCONTENT, ofsFirstValue);  // Write position of first value into key
            for (lpVC = lpKC->lpFirstVC; NULL != lpVC; lpVC = lpVC->lpBrotherVC) {
                // Get current file position
                // put in a separate var for later use
                nFPValue = fileextradata.ofsFBFile + fileextradata.ofsFBuffer;

                // Write position of current reg value in caller's field
                if (0 < nFPCaller) {
                    WriteFileBuffer(nFPCaller, &nFPValue, sizeof(nFPValue));
                }

                // Initialize value content

                // Copy values
                sVC.nTypeCode = lpVC->nTypeCode;
                sVC.cbData = lpVC->cbData;

                // Set file positions of the relatives inside the tree
#ifdef _UNICODE
                sVC.ofsValueName = 0;       // not known yet, may be defined in this iteration
#endif
#ifndef _UNICODE
                // Value name will always be stored behind the structure, so its position is already known
                sVC.ofsValueName = nFPValue + sizeof(sVC);
#endif
                sVC.ofsValueData = 0;       // not known yet, may be re-written in this iteration
                sVC.ofsBrotherValue = 0;    // not known yet, may be re-written in next iteration
                sVC.ofsFatherKey = nFPKey;

                // New since value content version 2
                sVC.nValueNameLen = 0;

                // Determine value name length
                if (NULL != lpVC->lpszValueName) {
                    sVC.nValueNameLen = (DWORD)lpVC->cchValueName;
                    if (0 < sVC.nValueNameLen) {  // otherwise leave it all 0
                        sVC.nValueNameLen++;  // account for NULL char
#ifdef _UNICODE
                        // Value name will always be stored behind the structure, so its position is already known
                        sVC.ofsValueName = nFPValue + sizeof(sVC);
#endif
                    }
                }

                // Increase count
                cCurrent++;

                // Write value content to file
                // Make sure that ALL fields have been initialized/set
                WriteFileBuffer(-1, &sVC, sizeof(sVC));

                // Write value name to file
                if (0 < sVC.nValueNameLen) {
                    WriteFileBuffer(-1, lpVC->lpszValueName, sVC.nValueNameLen * sizeof(TCHAR));
#ifndef _UNICODE
                }
                else {
                    // Write empty string for backward compatibility
                    WriteFileBuffer(-1, lpszEmpty, 1 * sizeof(TCHAR));
#endif
                }

                // Write value data to file
                if (0 < sVC.cbData) {
                    DWORD nFPValueData;

                    // Write position of value data in value content field ofsValueData
                    nFPValueData = fileextradata.ofsFBFile + fileextradata.ofsFBuffer;

                    WriteFileBuffer(nFPValue + offsetof(SAVEVALUECONTENT, ofsValueData), &nFPValueData, sizeof(nFPValueData));

                    // Write value data
                    WriteFileBuffer(-1, lpVC->lpValueData, sVC.cbData);
                }

                // Set "ofsBrotherValue" position for storing the following brother's position
                nFPCaller = nFPValue + offsetof(SAVEVALUECONTENT, ofsBrotherValue);
            }
        }

        // Update progress bar display
        if (0 != cEnd) {
            nCurrentTime = GetTickCount();
            if (REFRESHINTERVAL < (nCurrentTime - nLastTime)) {
                UI_UpdateProgressBar();
            }
        }

        // ATTENTION!!! sKC will be INVALID from this point on, due to recursive calls
        // If the entry has childs, then do a recursive call for the first child
        // Pass this entry as father and "ofsFirstSubKey" position for storing the first child's position
        if (NULL != lpKC->lpFirstSubKC) {
            SaveRegKeys(lpShot, lpKC->lpFirstSubKC, nFPKey, nFPKey + offsetof(SAVEKEYCONTENT, ofsFirstSubKey));
        }

        // Set "ofsBrotherKey" position for storing the following brother's position
        nFPCaller = nFPKey + offsetof(SAVEKEYCONTENT, ofsBrotherKey);
    }
}


// ----------------------------------------------------------------------
// Save registry and files to HIVE file
// ----------------------------------------------------------------------
#ifdef _WINDOWS
VOID SaveShot(LPREGSHOT lpShot)
{
    OPENFILENAME opfn;
    TCHAR filepath[MAX_PATH];
#endif
#ifdef _CONSOLE
    VOID SaveShot(LPREGSHOT lpShot, TCHAR * filepath)
    {
#endif
        DWORD nFPCurrent;

        // Check if there's anything to save
        if ((NULL == lpShot->lpHKLM) && (NULL == lpShot->lpHKU) && (NULL == lpShot->lpHF)) {
            return;  // leave silently
        }

#ifdef _WINDOWS
        // Clear Save File Name result buffer
        ZeroMemory(filepath, sizeof(filepath));

        // Prepare Save File Name dialog
        ZeroMemory(&opfn, sizeof(opfn));
        opfn.lStructSize = sizeof(opfn);
        opfn.hwndOwner = hWnd;
        opfn.lpstrFilter = lpszFilter;
        opfn.lpstrFile = filepath;
        opfn.nMaxFile = MAX_PATH;  // incl. NULL character
        opfn.lpstrInitialDir = lpszLastSaveDir;
        opfn.Flags = OFN_OVERWRITEPROMPT | OFN_HIDEREADONLY;
        opfn.lpstrDefExt = lpszRegshotFileDefExt;

        // Display Save File Name dialog
        if (!GetSaveFileName(&opfn)) {
            if (CommDlgExtendedError() != 0)
                ErrMsg(TEXT("The save dialog could not be opened. The snapshot remains in memory; retry Save."));
            return;  // leave silently
        }

        // Open file for writing
        hFileWholeReg = CreateFile(opfn.lpstrFile, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
#endif
#ifdef _CONSOLE
        hFileWholeReg = CreateFile(filepath, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
#endif
        if (INVALID_HANDLE_VALUE == hFileWholeReg) {
            ErrMsg(asLangTexts[iszTextErrorCreateFile].lpszText);
            return;
        }
        fHiveWriteFailed = FALSE;

        // Setup GUI for saving...
        cEnd = lpShot->stCounts.cAll;
        UI_InitProgressBar();

        // Initialize file header
        ZeroMemory(&fileheader, sizeof(fileheader));
        ZeroMemory(&fileextradata, sizeof(fileextradata));

        // Copy SBCS/MBCS signature to header (even in Unicode builds for backwards compatibility)
        strncpy_s(fileheader.signature, MAX_SIGNATURE_LENGTH, szRegshotFileSignature, MAX_SIGNATURE_LENGTH);

        // Set file positions of hives inside the file
        fileheader.ofsHKLM = 0;   // not known yet, may be empty
        fileheader.ofsHKU = 0;    // not known yet, may be empty
        fileheader.ofsHF = 0;  // not known yet, may be empty

        // Copy SBCS/MBCS strings to header (even in Unicode builds for backwards compatibility)
        if (NULL != lpShot->lpszComputerName) {
#ifdef _UNICODE
            WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK | WC_DEFAULTCHAR, lpShot->lpszComputerName, -1, fileheader.computername, OLD_COMPUTERNAMELEN, NULL, NULL);
#else
            strncpy(fileheader.computername, lpShot->lpszComputerName, OLD_COMPUTERNAMELEN);
#endif
        }
        if (NULL != lpShot->lpszUserName) {
#ifdef _UNICODE
            WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK | WC_DEFAULTCHAR, lpShot->lpszUserName, -1, fileheader.username, OLD_COMPUTERNAMELEN, NULL, NULL);
#else
            strncpy(fileheader.username, lpShot->lpszUserName, OLD_COMPUTERNAMELEN);
#endif
        }

        // Copy system time to header
        CopyMemory(&fileheader.systemtime, &lpShot->systemtime, sizeof(SYSTEMTIME));

        // new since header version 2
        fileheader.nFHSize = sizeof(fileheader);

        fileheader.nFHVersion = FILEHEADER_VERSION_CURRENT;
        fileheader.nCharSize = sizeof(TCHAR);

        fileheader.ofsComputerName = 0;  // not known yet, may be empty
        fileheader.nComputerNameLen = 0;
        if (NULL != lpShot->lpszComputerName) {
            fileheader.nComputerNameLen = (DWORD)_tcslen(lpShot->lpszComputerName);
            if (0 < fileheader.nComputerNameLen) {
                fileheader.nComputerNameLen++;  // account for NULL char
            }
        }

        fileheader.ofsUserName = 0;      // not known yet, may be empty
        fileheader.nUserNameLen = 0;
        if (NULL != lpShot->lpszUserName) {
            fileheader.nUserNameLen = (DWORD)_tcslen(lpShot->lpszUserName);
            if (0 < fileheader.nUserNameLen) {
                fileheader.nUserNameLen++;  // account for NULL char
            }
        }

        fileheader.nKCVersion = KEYCONTENT_VERSION_CURRENT;
        fileheader.nKCSize = sizeof(SAVEKEYCONTENT);

        fileheader.nVCVersion = VALUECONTENT_VERSION_CURRENT;
        fileheader.nVCSize = sizeof(SAVEVALUECONTENT);

        fileheader.nHFVersion = HEADFILE_VERSION_CURRENT;
        fileheader.nHFSize = sizeof(SAVEHEADFILE);

        fileheader.nFCVersion = FILECONTENT_VERSION_CURRENT;
        fileheader.nFCSize = sizeof(SAVEFILECONTENT);

        fileheader.nEndianness = FILEHEADER_ENDIANNESS_VALUE;

        // Write header to file
        WriteFileBuffer(-1, &fileheader, sizeof(fileheader));

        // new since header version 2
        // (v2) full computername
        if (0 < fileheader.nComputerNameLen) {
            // Write position in file header
            nFPCurrent = fileextradata.ofsFBFile + fileextradata.ofsFBuffer;

            WriteFileBuffer(offsetof(FILEHEADER, ofsComputerName), &nFPCurrent, sizeof(nFPCurrent));
            fileheader.ofsComputerName = nFPCurrent;  // keep track in memory too

            // Write computername
            WriteFileBuffer(-1, lpShot->lpszComputerName, fileheader.nComputerNameLen * sizeof(TCHAR));
        }

        // (v2) full username
        if (0 < fileheader.nUserNameLen) {
            // Write position in file header
            nFPCurrent = fileextradata.ofsFBFile + fileextradata.ofsFBuffer;

            WriteFileBuffer(offsetof(FILEHEADER, ofsUserName), &nFPCurrent, sizeof(nFPCurrent));
            fileheader.ofsUserName = nFPCurrent;  // keep track in memory too

            // Write username
            WriteFileBuffer(-1, lpShot->lpszUserName, fileheader.nUserNameLen * sizeof(TCHAR));
        }

        // Save HKLM
        if (NULL != lpShot->lpHKLM) {
            SaveRegKeys(lpShot, lpShot->lpHKLM, 0, offsetof(FILEHEADER, ofsHKLM));

            // Update progress bar display (keys/values final)
            if (0 != cEnd) {
                nCurrentTime = GetTickCount();
                UI_UpdateProgressBar();
            }
        }

        // Save HKU
        if (NULL != lpShot->lpHKU) {
            SaveRegKeys(lpShot, lpShot->lpHKU, 0, offsetof(FILEHEADER, ofsHKU));

            // Update progress bar display (keys/values final)
            if (0 != cEnd) {
                nCurrentTime = GetTickCount();
                UI_UpdateProgressBar();
            }
        }

        // Save HEADFILEs
        if (NULL != lpShot->lpHF) {
            SaveHeadFiles(lpShot, lpShot->lpHF, offsetof(FILEHEADER, ofsHF));

            // Update progress bar display (dirs/files final)
            if (0 != cEnd) {
                nCurrentTime = GetTickCount();
                UI_UpdateProgressBar();
            }
        }

        // Close file
        EmptyFileBuffer();
        if (!CloseHandle(hFileWholeReg)) {
            fHiveWriteFailed = TRUE;
        }
#ifdef _WINDOWS
        // The most recently saved shot becomes the USN baseline, only if fully written
        SaveUsnBaseline(lpShot, !fHiveWriteFailed);
#endif

        if (NULL != lpFileBuffer) {
            MYFREE(lpFileBuffer);
            lpFileBuffer = NULL;
        }

        // Update progress bar display (final)
        if (0 != cEnd) {
            nCurrentTime = GetTickCount();
            UI_UpdateProgressBar();
        }

        UI_ShowHideProgressBar(SW_HIDE);

        if (fHiveWriteFailed) {
            ErrMsg(TEXT("The snapshot could not be fully written. The saved file is incomplete; check free space and retry Save."));
        }

#ifdef _WINDOWS
        // overwrite first letter of file name with NULL character to get path only, then create backup for initialization on next call
        * (opfn.lpstrFile + opfn.nFileOffset) = (TCHAR)'\0';  // TODO: check
        _tcscpy_s(lpszLastSaveDir, MAX_PATH, opfn.lpstrFile);
#endif
    }


    // ----------------------------------------------------------------------
    //
    // ----------------------------------------------------------------------
    size_t AdjustBuffer(LPVOID * lpBuffer, size_t nCurrentSize, size_t nWantedSize, size_t nAlign)
    {
        if (NULL == *lpBuffer) {
            nCurrentSize = 0;
        }

        if (nWantedSize > nCurrentSize) {
            if (NULL != *lpBuffer) {
                MYFREE(*lpBuffer);
                *lpBuffer = NULL;
            }

            if (1 >= nAlign) {
                nCurrentSize = nWantedSize;
            }
            else {
                nCurrentSize = nWantedSize / nAlign;
                nCurrentSize *= nAlign;
                if (nWantedSize > nCurrentSize) {
                    nCurrentSize += nAlign;
                }
            }

            *lpBuffer = MYALLOC(nCurrentSize);
        }

        return nCurrentSize;
    }


    // ----------------------------------------------------------------------
    // Load registry key with values from HIVE file
    // ----------------------------------------------------------------------
    VOID LoadRegKeys(LPREGSHOT lpShot, DWORD ofsKey, LPKEYCONTENT lpFatherKC, LPKEYCONTENT * lplpCaller)
    {
        LPKEYCONTENT lpKC;
        DWORD ofsBrotherKey;

        // Read all reg keys and their value and sub key contents
        for (; !lpShot->fIncomplete && 0 != ofsKey; ofsKey = ofsBrotherKey) {
            // Copy SAVEKEYCONTENT to aligned memory block
            ZeroMemory(&sKC, sizeof(sKC));
            CopyMemory(&sKC, (lpFileBuffer + ofsKey), fileheader.nKCSize);

            // Save offsets in local variables due to recursive calls
            ofsBrotherKey = sKC.ofsBrotherKey;

            // Create new key content
            // put in a separate var for later use
            lpKC = MYALLOC0(sizeof(KEYCONTENT));
            if (lpKC == NULL) {
                lpShot->fIncomplete = TRUE;
                return;
            }

            // Set father of current key
            lpKC->lpFatherKC = lpFatherKC;

            // Copy key name
            if (fileextradata.bOldKCVersion) {  // old SBCS/MBCS version
                sKC.nKeyNameLen = (DWORD)strlen((const char*)(lpFileBuffer + sKC.ofsKeyName));
                if (0 < sKC.nKeyNameLen) {
                    sKC.nKeyNameLen++;  // account for NULL char
                }
            }
            if (0 < sKC.nKeyNameLen) {  // otherwise leave it NULL
                // Copy string to an aligned memory block
                nSourceSize = sKC.nKeyNameLen * fileheader.nCharSize;
                nStringBufferSize = AdjustBuffer(&lpStringBuffer, nStringBufferSize, nSourceSize, REGSHOT_BUFFER_BLOCK_BYTES);
                if (lpStringBuffer == NULL) {
                    lpShot->fIncomplete = TRUE;
                    FreeAllKeyContents(lpKC);
                    return;
                }
                ZeroMemory(lpStringBuffer, nStringBufferSize);
                CopyMemory(lpStringBuffer, (lpFileBuffer + sKC.ofsKeyName), nSourceSize);

                lpKC->lpszKeyName = MYALLOC0((sKC.nKeyNameLen+1)  * sizeof(TCHAR));
                if (lpKC->lpszKeyName == NULL) {
                    lpShot->fIncomplete = TRUE;
                    FreeAllKeyContents(lpKC);
                    return;
                }
                if (fileextradata.bSameCharSize) {
                    _tcsncpy_s(lpKC->lpszKeyName, sKC.nKeyNameLen + 1, lpStringBuffer, sKC.nKeyNameLen);
                }
                else {
#ifdef _UNICODE
                    MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, (LPCSTR)lpStringBuffer, -1, lpKC->lpszKeyName, sKC.nKeyNameLen);
#else
                    WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK | WC_DEFAULTCHAR, (LPCWSTR)lpStringBuffer, -1, lpKC->lpszKeyName, sKC.nKeyNameLen, NULL, NULL);
#endif
                }
                lpKC->lpszKeyName[sKC.nKeyNameLen - 1] = (TCHAR)'\0';  // safety NULL char

                // Set key name length in chars
                lpKC->cchKeyName = _tcslen(lpKC->lpszKeyName);
            }

            // Adopt to short HKLM/HKU
            if (NULL == lpKC->lpFatherKC) {
                if ((0 == _tcscmp(lpKC->lpszKeyName, lpszHKLMShort))
                    || (0 == _tcscmp(lpKC->lpszKeyName, lpszHKLMLong))) {
                    MYFREE(lpKC->lpszKeyName);
                    lpKC->lpszKeyName = lpszHKLMShort;
                    lpKC->cchKeyName = _tcslen(lpKC->lpszKeyName);
                }
                else if ((0 == _tcscmp(lpKC->lpszKeyName, lpszHKUShort))
                    || (0 == _tcscmp(lpKC->lpszKeyName, lpszHKULong))) {
                    MYFREE(lpKC->lpszKeyName);
                    lpKC->lpszKeyName = lpszHKUShort;
                    lpKC->cchKeyName = _tcslen(lpKC->lpszKeyName);
                }
            }

            // Check if key is to be excluded
            if (NULL != lprgszRegSkipStrings[0]) {  // only if there is something to exclude
                LPTSTR lpszFullName;

                if ((NULL != lpKC->lpszKeyName) && (IsInSkipList(lpKC->lpszKeyName, lprgszRegSkipStrings))) {
                    FreeAllKeyContents(lpKC);
                    continue;  // ignore this entry and continue with next brother key
                }

                lpszFullName = GetWholeKeyName(lpKC, FALSE);
                if (lpszFullName == NULL) {
                    lpShot->fIncomplete = TRUE;
                    FreeAllKeyContents(lpKC);
                    return;
                }
                if (IsInSkipList(lpszFullName, lprgszRegSkipStrings)) {
                    MYFREE(lpszFullName);
                    FreeAllKeyContents(lpKC);
                    continue;  // ignore this entry and continue with next brother key
                }
                MYFREE(lpszFullName);
            }

            // Copy pointer to current key into caller's pointer
            if (NULL != lplpCaller) {
                *lplpCaller = lpKC;
            }

            // Increase key count
            lpShot->stCounts.cKeys++;
            lpKC->nScanError = sKC.nScanError;
            if (lpKC->nScanError != 0)
                ++lpShot->cSkippedRegKeys;

            // Copy the value contents of the current key
            if (0 != sKC.ofsFirstValue) {
                LPVALUECONTENT lpVC;
                LPVALUECONTENT* lplpCallerVC;
                DWORD ofsValue;
                LPTSTR lpszFullName;

                // Read all values of key
                lplpCallerVC = &lpKC->lpFirstVC;
                for (ofsValue = sKC.ofsFirstValue; 0 != ofsValue; ofsValue = sVC.ofsBrotherValue) {
                    // Copy SAVEVALUECONTENT to aligned memory block
                    ZeroMemory(&sVC, sizeof(sVC));
                    CopyMemory(&sVC, (lpFileBuffer + ofsValue), fileheader.nVCSize);

                    // Create new value content
                    lpVC = MYALLOC0(sizeof(VALUECONTENT));
                    if (lpVC == NULL) {
                        lpShot->fIncomplete = TRUE;
                        return;
                    }

                    // Set father key of current value to current key
                    lpVC->lpFatherKC = lpKC;

                    // Copy value name
                    if (fileextradata.bOldVCVersion) {  // old SBCS/MBCS version
                        sVC.nValueNameLen = (DWORD)strlen((const char*)(lpFileBuffer + sVC.ofsValueName));
                        if (0 < sVC.nValueNameLen) {
                            sVC.nValueNameLen++;  // account for NULL char
                        }
                    }
                    if (0 < sVC.nValueNameLen) {  // otherwise leave it NULL
                        // Copy string to an aligned memory block
                        nSourceSize = sVC.nValueNameLen * fileheader.nCharSize;
                        nStringBufferSize = AdjustBuffer(&lpStringBuffer, nStringBufferSize, nSourceSize, REGSHOT_BUFFER_BLOCK_BYTES);
                        if (lpStringBuffer == NULL) {
                            lpShot->fIncomplete = TRUE;
                            FreeAllValueContents(lpVC);
                            return;
                        }
                        ZeroMemory(lpStringBuffer, nStringBufferSize);
                        CopyMemory(lpStringBuffer, (lpFileBuffer + sVC.ofsValueName), nSourceSize);

                        lpVC->lpszValueName = MYALLOC((sVC.nValueNameLen + 1) * sizeof(TCHAR));
                        if (lpVC->lpszValueName == NULL) {
                            lpShot->fIncomplete = TRUE;
                            FreeAllValueContents(lpVC);
                            return;
                        }
                        if (fileextradata.bSameCharSize) {
                            _tcsncpy_s(lpVC->lpszValueName, sVC.nValueNameLen + 1, lpStringBuffer, sVC.nValueNameLen);
                        }
                        else {
#ifdef _UNICODE
                            MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, (LPCSTR)lpStringBuffer, -1, lpVC->lpszValueName, sVC.nValueNameLen);
#else
                            WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK | WC_DEFAULTCHAR, (LPCWSTR)lpStringBuffer, -1, lpVC->lpszValueName, sVC.nValueNameLen, NULL, NULL);
#endif
                        }
                        lpVC->lpszValueName[sVC.nValueNameLen - 1] = (TCHAR)'\0';  // safety NULL char

                        // Set value name length in chars
                        lpVC->cchValueName = _tcslen(lpVC->lpszValueName);
                    }

                    // Check if value is to be excluded
                    if (NULL != lprgszRegSkipStrings[0]) {  // only if there is something to exclude
                        if ((NULL != lpVC->lpszValueName) && (IsInSkipList(lpVC->lpszValueName, lprgszRegSkipStrings))) {
                            FreeAllValueContents(lpVC);
                            continue;  // ignore this entry and continue with next brother value
                        }

                        lpszFullName = GetWholeValueName(lpVC, FALSE);
                        if (lpszFullName == NULL) {
                            lpShot->fIncomplete = TRUE;
                            FreeAllValueContents(lpVC);
                            return;
                        }
                        if (IsInSkipList(lpszFullName, lprgszRegSkipStrings)) {
                            MYFREE(lpszFullName);
                            FreeAllValueContents(lpVC);
                            continue;  // ignore this entry and continue with next brother value
                        }
                        MYFREE(lpszFullName);
                    }

                    // Copy pointer to current value into previous value's next value pointer
                    if (NULL != lplpCallerVC) {
                        *lplpCallerVC = lpVC;
                    }

                    // Increase value count
                    lpShot->stCounts.cValues++;

                    // Copy value meta data
                    lpVC->nTypeCode = sVC.nTypeCode;
                    lpVC->cbData = sVC.cbData;

                    // Copy value data
                    if (0 < sVC.cbData) {  // otherwise leave it NULL
                        lpVC->lpValueData = MYALLOC(sVC.cbData);
                        if (lpVC->lpValueData == NULL) {
                            lpShot->fIncomplete = TRUE;
                            return;
                        }
                        CopyMemory(lpVC->lpValueData, (lpFileBuffer + sVC.ofsValueData), sVC.cbData);
                    }

                    // Set "lpBrotherVC" pointer for storing the next brother's pointer
                    lplpCallerVC = &lpVC->lpBrotherVC;
                }
            }

            // Update counters display
            nCurrentTime = GetTickCount();
            if (REFRESHINTERVAL < (nCurrentTime - nLastTime)) {
                UI_UpdateCounters(asLangTexts[iszTextKey].lpszText, asLangTexts[iszTextValue].lpszText, lpShot->stCounts.cKeys, lpShot->stCounts.cValues);
            }

            // ATTENTION!!! sKC will be INVALID from this point on, due to recursive calls
            // If the entry has childs, then do a recursive call for the first child
            // Pass this entry as father and "lpFirstSubKC" pointer for storing the first child's pointer
            if (0 != sKC.ofsFirstSubKey) {
                LoadRegKeys(lpShot, sKC.ofsFirstSubKey, lpKC, &lpKC->lpFirstSubKC);
            }

            // Set "lpBrotherKC" pointer for storing the next brother's pointer
            lplpCaller = &lpKC->lpBrotherKC;
        }
    }


    typedef struct {
        const BYTE* data;
        DWORD size;
        const FILEHEADER* header;
        BYTE* visited;
    } HIVE_VALIDATION;

    static BOOL HiveRange(const HIVE_VALIDATION* hive, DWORD offset, ULONGLONG size)
    {
        DWORD headerSize = hive->header->nFHSize != 0
            ? hive->header->nFHSize : (DWORD)offsetof(FILEHEADER, nFHVersion);

        return offset >= headerSize && offset <= hive->size && size <= hive->size - offset;
    }

    static BOOL HiveNode(HIVE_VALIDATION* hive, DWORD offset, DWORD size)
    {
        BYTE bit = (BYTE)(1 << (offset & 7));

        if (!HiveRange(hive, offset, size) || (hive->visited[offset >> 3] & bit))
            return FALSE;
        hive->visited[offset >> 3] |= bit;
        return TRUE;
    }

    static BOOL HiveString(const HIVE_VALIDATION* hive, DWORD offset, DWORD count,
        BOOL old, BOOL required)
    {
        DWORD width = hive->header->nCharSize;
        WCHAR last = 0;

        if (old) {
            const BYTE* end;

            if (!HiveRange(hive, offset, 1))
                return !required && offset == 0;
            end = memchr(hive->data + offset, 0, hive->size - offset);
            return end != NULL && (!required || end != hive->data + offset);
        }
        if (count == 0) {
            if (required)
                return FALSE;
            if (offset == 0)
                return TRUE;
            if (!HiveRange(hive, offset, width))
                return FALSE;
            memcpy(&last, hive->data + offset, width);
            return last == 0;
        }
        if (!HiveRange(hive, offset, (ULONGLONG)count * width))
            return FALSE;
        memcpy(&last, hive->data + offset + ((size_t)count - 1) * width, width);
        return last == 0 && (!required || count > 1);
    }

    static BOOL ValidateHiveKeys(HIVE_VALIDATION* hive, DWORD offset, unsigned depth)
    {
        if (depth > 512)
            return FALSE;
        while (offset != 0) {
            SAVEKEYCONTENT key = { 0 };
            DWORD valueOffset;

            if (!HiveNode(hive, offset, hive->header->nKCSize))
                return FALSE;
            memcpy(&key, hive->data + offset, hive->header->nKCSize);
            if (!HiveString(hive, key.ofsKeyName, key.nKeyNameLen,
                    hive->header->nKCVersion < KEYCONTENT_VERSION_2, TRUE))
                return FALSE;
            for (valueOffset = key.ofsFirstValue; valueOffset != 0;) {
                SAVEVALUECONTENT value = { 0 };

                if (!HiveNode(hive, valueOffset, hive->header->nVCSize))
                    return FALSE;
                memcpy(&value, hive->data + valueOffset, hive->header->nVCSize);
                if (!HiveString(hive, value.ofsValueName, value.nValueNameLen,
                        hive->header->nVCVersion < VALUECONTENT_VERSION_2, FALSE)
                    || (value.cbData != 0 && !HiveRange(hive, value.ofsValueData, value.cbData)))
                    return FALSE;
                valueOffset = value.ofsBrotherValue;
            }
            if (!ValidateHiveKeys(hive, key.ofsFirstSubKey, depth + 1))
                return FALSE;
            offset = key.ofsBrotherKey;
        }
        return TRUE;
    }

    static BOOL ValidateHiveFiles(HIVE_VALIDATION* hive, DWORD offset, unsigned depth)
    {
        if (depth > 512)
            return FALSE;
        while (offset != 0) {
            SAVEFILECONTENT file = { 0 };

            if (!HiveNode(hive, offset, hive->header->nFCSize))
                return FALSE;
            memcpy(&file, hive->data + offset, hive->header->nFCSize);
            if (!HiveString(hive, file.ofsFileName, file.nFileNameLen,
                    hive->header->nFCVersion < FILECONTENT_VERSION_2, TRUE)
                || (file.nScanError != 0
                    && (!(file.nFileAttributes & FILE_ATTRIBUTE_DIRECTORY) || file.ofsFirstSubFile != 0))
                || !ValidateHiveFiles(hive, file.ofsFirstSubFile, depth + 1))
                return FALSE;
            offset = file.ofsBrotherFile;
        }
        return TRUE;
    }

    // Validate every reachable range and reject cycles before recursive loaders run.
    static BOOL ValidateHive(const BYTE* data, DWORD size, const FILEHEADER* header)
    {
        HIVE_VALIDATION hive;
        DWORD offset;
        BOOL valid;

        if (header->nFHVersion < FILEHEADER_VERSION_1 || header->nFHVersion > FILEHEADER_VERSION_CURRENT
            || (header->nFHSize != 0 && (header->nFHSize > size
                || header->nFHSize < (header->nFHVersion >= FILEHEADER_VERSION_2
                    ? sizeof(FILEHEADER) : offsetof(FILEHEADER, nFHVersion))))
            || (header->nCharSize != 1 && header->nCharSize != 2)
            || header->nKCVersion < 1 || header->nKCVersion > KEYCONTENT_VERSION_CURRENT
            || header->nVCVersion < 1 || header->nVCVersion > VALUECONTENT_VERSION_CURRENT
            || header->nHFVersion != HEADFILE_VERSION_CURRENT
            || header->nFCVersion < 1 || header->nFCVersion > FILECONTENT_VERSION_CURRENT
            || header->nKCSize != (header->nKCVersion < 2 ? offsetof(SAVEKEYCONTENT, nKeyNameLen)
                : header->nKCVersion < 3 ? offsetof(SAVEKEYCONTENT, nScanError) : sizeof(SAVEKEYCONTENT))
            || header->nVCSize != (header->nVCVersion < 2 ? offsetof(SAVEVALUECONTENT, nValueNameLen) : sizeof(SAVEVALUECONTENT))
            || header->nHFSize != sizeof(SAVEHEADFILE)
            || header->nFCSize != (header->nFCVersion < 2 ? offsetof(SAVEFILECONTENT, nFileNameLen)
                : header->nFCVersion < 3 ? offsetof(SAVEFILECONTENT, nHashLow)
                : header->nFCVersion < 4 ? offsetof(SAVEFILECONTENT, nScanError) : sizeof(SAVEFILECONTENT)))
            return FALSE;
        hive.data = data;
        hive.size = size;
        hive.header = header;
        hive.visited = calloc((size_t)size / 8 + 1, 1);
        if (hive.visited == NULL)
            return FALSE;
        valid = (header->nFHVersion < FILEHEADER_VERSION_2
                || (HiveString(&hive, header->ofsComputerName, header->nComputerNameLen, FALSE, FALSE)
                    && HiveString(&hive, header->ofsUserName, header->nUserNameLen, FALSE, FALSE)))
            && ValidateHiveKeys(&hive, header->ofsHKLM, 0)
            && ValidateHiveKeys(&hive, header->ofsHKU, 0);
        for (offset = header->ofsHF; valid && offset != 0;) {
            SAVEHEADFILE head;

            valid = HiveNode(&hive, offset, header->nHFSize);
            if (!valid)
                break;
            memcpy(&head, data + offset, sizeof(head));
            valid = ValidateHiveFiles(&hive, head.ofsFirstFileContent, 0);
            offset = head.ofsBrotherHeadFile;
        }
        free(hive.visited);
        return valid;
    }

    // ----------------------------------------------------------------------
    // Load registry and files from HIVE file
    // ----------------------------------------------------------------------
    BOOL LoadShot(LPREGSHOT lpShot)
    {
        OPENFILENAME opfn;
        TCHAR filepath[MAX_PATH];  // length incl. NULL character

        DWORD cbFileSize;
        DWORD cbFileRemain;
        DWORD cbReadSize;
        DWORD cbFileRead;
        LARGE_INTEGER fileSize;
        REGSHOT loadedShot = { 0 };
        LPREGSHOT originalShot = lpShot;

        // Clear Get File Name result buffer
        ZeroMemory(filepath, sizeof(filepath));

        // Prepare Open File Name dialog
        ZeroMemory(&opfn, sizeof(opfn));
#ifdef _WINDOWS
        opfn.lStructSize = sizeof(opfn);
        opfn.hwndOwner = hWnd;
        opfn.lpstrFilter = lpszFilter;
        opfn.lpstrFile = filepath;
        opfn.nMaxFile = MAX_PATH;  // incl. NULL character
        opfn.lpstrInitialDir = lpszLastOpenDir;
        opfn.Flags = OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
        opfn.lpstrDefExt = lpszRegshotFileDefExt;
#endif

        // Display Open File Name dialog
        if (!GetOpenFileName(&opfn)) {
            return FALSE;
        }

        // Open file for reading
        hFileWholeReg = CreateFile(opfn.lpstrFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
        if (INVALID_HANDLE_VALUE == hFileWholeReg) {
            ErrMsg(asLangTexts[iszTextErrorOpenFile].lpszText);
            return FALSE;
        }

        if (!GetFileSizeEx(hFileWholeReg, &fileSize) || fileSize.QuadPart > MAXLONG
            || fileSize.QuadPart < offsetof(FILEHEADER, nFHVersion)) {
            CloseHandle(hFileWholeReg);
            ErrMsg(TEXT("wrong filesize"));  //TODO: I18N, create text index and translate
            return FALSE;
        }
        cbFileSize = (DWORD)fileSize.QuadPart;

        // Initialize file header
        ZeroMemory(&fileheader, sizeof(fileheader));
        ZeroMemory(&fileextradata, sizeof(fileextradata));

        // Read first part of file header from file (signature, nHeaderSize)
        if (!ReadFile(hFileWholeReg, &fileheader, offsetof(FILEHEADER, ofsHKLM), &NBW, NULL)
            || NBW != offsetof(FILEHEADER, ofsHKLM)) {
            CloseHandle(hFileWholeReg);
            ErrMsg(TEXT("Reading ERROR!"));
            return FALSE;
        }

        // Check for valid file signatures (SBCS/MBCS and UTF-16 signature)
        if ((0 != strncmp(szRegshotFileSignatureSBCS, fileheader.signature, MAX_SIGNATURE_LENGTH)) && (0 != strncmp(szRegshotFileSignatureUTF16, fileheader.signature, MAX_SIGNATURE_LENGTH))) {
            CloseHandle(hFileWholeReg);
            ErrMsg(TEXT("It is not a Regshot hive file!"));  //TODO: I18N, create text index and translate
            return FALSE;
        }

        // Check file signature for correct type (SBCS/MBCS or UTF-16)
        if (0 != strncmp(szRegshotFileSignature, fileheader.signature, MAX_SIGNATURE_LENGTH)) {
            CloseHandle(hFileWholeReg);
#ifdef _UNICODE
            ErrMsg(TEXT("It is not a Unicode Regshot hive file! Try the ANSI version with it."));  //TODO: I18N, create text index and translate
#else
            ErrMsg(TEXT("It is not an ANSI Regshot hive file! Try the Unicode version with it."));  //TODO: I18N, create text index and translate
#endif
            return FALSE;
        }

        // Allocate memory to hold the complete file
        lpFileBuffer = MYALLOC(cbFileSize);
        if (lpFileBuffer == NULL) {
            CloseHandle(hFileWholeReg);
            ErrMsg(TEXT("Not enough memory to load the snapshot."));
            return FALSE;
        }

        // Setup GUI for loading...
        cEnd = cbFileSize;
        UI_InitProgressBar();

        // Read file blockwise for progress bar
        SetFilePointer(hFileWholeReg, 0, NULL, FILE_BEGIN);
        cbFileRemain = cbFileSize;  // 100% to go
        cbReadSize = REGSHOT_READ_BLOCK_SIZE;  // next block length to read
        for (cbFileRead = 0; 0 < cbFileRemain; cbFileRead += cbReadSize) {
            // If the rest is smaller than a block, then use the rest length
            if (REGSHOT_READ_BLOCK_SIZE > cbFileRemain) {
                cbReadSize = cbFileRemain;
            }

            // Read the next block
            if (!ReadFile(hFileWholeReg, lpFileBuffer + cbFileRead, cbReadSize, &NBW, NULL)
                || NBW != cbReadSize) {
                CloseHandle(hFileWholeReg);
                MYFREE(lpFileBuffer);
                lpFileBuffer = NULL;
                UI_ShowHideProgressBar(SW_HIDE);
                ErrMsg(TEXT("Reading ERROR!"));  //TODO: I18N, create text index and translate
                return FALSE;
            }

            // Determine how much to go, if zero leave the for-loop
            cbFileRemain -= cbReadSize;
            if (0 == cbFileRemain) {
                break;
            }

            // Update progress bar display
            if (0 != cEnd) {
                nCurrentTime = GetTickCount();
                if (REFRESHINTERVAL < (nCurrentTime - nLastTime)) {
                    cCurrent = cbFileRead;
                    UI_UpdateProgressBar();
                }
            }
        }

        // Close file
        CloseHandle(hFileWholeReg);

        // Update progress bar display (load final)
        if (0 != cEnd) {
            nCurrentTime = GetTickCount();
            UI_UpdateProgressBar();
        }

        cEnd = 0;
        UI_ShowHideProgressBar(SW_HIDE);

        // Setup GUI for parsing loaded file...
        UI_InitCounters();

        // Check size for copying file header
        nSourceSize = fileheader.nFHSize;
        if (0 == nSourceSize) {
            nSourceSize = offsetof(FILEHEADER, nFHVersion);
        }
        else if (sizeof(fileheader) < nSourceSize) {
            nSourceSize = sizeof(fileheader);
        }

        // Copy file header to structure
        if (nSourceSize > cbFileSize || nSourceSize < offsetof(FILEHEADER, nFHVersion)) {
            MYFREE(lpFileBuffer);
            lpFileBuffer = NULL;
            UI_ShowHideCounters(SW_HIDE);
            ErrMsg(TEXT("Invalid snapshot header."));
            return FALSE;
        }
        ZeroMemory(&fileheader, sizeof(fileheader));
        CopyMemory(&fileheader, lpFileBuffer, nSourceSize);

        // Enhance data of old headers to be used with newer code
        if (FILEHEADER_VERSION_EMPTY == fileheader.nFHVersion) {
            if ((0 != fileheader.ofsHKLM) && (fileheader.ofsHKU == fileheader.ofsHKLM)) {
                fileheader.ofsHKLM = 0;
            }
            if ((0 != fileheader.ofsHKU) && (fileheader.ofsHF == fileheader.ofsHKU)) {
                fileheader.ofsHKU = 0;
            }

            fileheader.nFHVersion = FILEHEADER_VERSION_1;
            fileheader.nCharSize = 1;
            fileheader.nKCVersion = KEYCONTENT_VERSION_1;
            fileheader.nKCSize = offsetof(SAVEKEYCONTENT, nKeyNameLen);
            fileheader.nVCVersion = VALUECONTENT_VERSION_1;
            fileheader.nVCSize = offsetof(SAVEVALUECONTENT, nValueNameLen);
            fileheader.nHFVersion = HEADFILE_VERSION_1;
            fileheader.nHFSize = sizeof(SAVEHEADFILE);  // not changed yet, if it is then adopt to offsetof(SAVEHEADFILE, <first new field>)
            fileheader.nFCVersion = FILECONTENT_VERSION_1;
            fileheader.nFCSize = offsetof(SAVEFILECONTENT, nFileNameLen);
        }
        if (FILEHEADER_VERSION_2 >= fileheader.nFHVersion) {
            if (0 == fileheader.nEndianness) {
                *((unsigned char*)&fileheader.nEndianness) = 0x78;  // old existing versions were all little endian
                *((unsigned char*)&fileheader.nEndianness + 1) = 0x56;
                *((unsigned char*)&fileheader.nEndianness + 2) = 0x34;
                *((unsigned char*)&fileheader.nEndianness + 3) = 0x12;
            }
        }

        if (!ValidateHive(lpFileBuffer, cbFileSize, &fileheader)) {
            MYFREE(lpFileBuffer);
            lpFileBuffer = NULL;
            UI_ShowHideCounters(SW_HIDE);
            ErrMsg(TEXT("Invalid snapshot: damaged structures, strings, or cyclic links."));
            return FALSE;
        }

        // Check for incompatible char size (known: 1 = SBCS/MBCS, 2 = UTF-16)
        if (sizeof(TCHAR) == fileheader.nCharSize) {
            fileextradata.bSameCharSize = TRUE;
        }
        else {
            fileextradata.bSameCharSize = FALSE;
#ifdef _UNICODE
            if (1 == fileheader.nCharSize) {
                ErrMsg(TEXT("It is not a Unicode Regshot hive file! Try the ANSI version with it."));  //TODO: I18N, create text index and translate
            }
            else if (2 != fileheader.nCharSize) {
                ErrMsg(TEXT("Unknown character size! Maybe created by a newer Regshot version."));  //TODO: I18N, create text index and translate
            }
            else {
                ErrMsg(TEXT("Unsupported character size!"));  //TODO: I18N, create text index and translate
            }
#else
            ErrMsg(TEXT("It is not an ANSI Regshot hive file! Try the Unicode version with it."));  //TODO: I18N, create text index and translate
#endif
            if (NULL != lpFileBuffer) {
                MYFREE(lpFileBuffer);
                lpFileBuffer = NULL;
            }
            return FALSE;
        }

        // Check for incompatible endianness (known: Intel = Little Endian)
        if (FILEHEADER_ENDIANNESS_VALUE == fileheader.nEndianness) {
            fileextradata.bSameEndianness = TRUE;
        }
        else {
            fileextradata.bSameEndianness = FALSE;
#ifdef __LITTLE_ENDIAN__
            ErrMsg(TEXT("It is not a Little Endian Regshot hive file!"));  //TODO: I18N, create text index and translate
#else
            ErrMsg(TEXT("It is not a Big Endian Regshot hive file!"));  //TODO: I18N, create text index and translate
#endif
            if (NULL != lpFileBuffer) {
                MYFREE(lpFileBuffer);
                lpFileBuffer = NULL;
            }
            return FALSE;
        }

        if (KEYCONTENT_VERSION_2 > fileheader.nKCVersion) {  // old SBCS/MBCS version
            fileextradata.bOldKCVersion = TRUE;
        }
        else {
            fileextradata.bOldKCVersion = FALSE;
        }

        if (VALUECONTENT_VERSION_2 > fileheader.nVCVersion) {  // old SBCS/MBCS version
            fileextradata.bOldVCVersion = TRUE;
        }
        else {
            fileextradata.bOldVCVersion = FALSE;
        }

        if (FILECONTENT_VERSION_2 > fileheader.nFCVersion) {  // old SBCS/MBCS version
            fileextradata.bOldFCVersion = TRUE;
        }
        else {
            fileextradata.bOldFCVersion = FALSE;
        }

        // ^^^ here the file header can be checked for additional extended content
        // * remember that files from older versions do not provide these additional data

        // Build separately so allocation failures preserve the previous shot too.
        cEnd = 0;
        lpShot = &loadedShot;

        // New temporary string buffer
        lpStringBuffer = NULL;

        // Copy computer name from file header to shot data
        if (FILEHEADER_VERSION_1 < fileheader.nFHVersion) {  // newer Unicode/SBCS/MBCS version
            if (0 < fileheader.nComputerNameLen) {  // otherwise leave it NULL
                // Copy string to an aligned memory block
                nSourceSize = fileheader.nComputerNameLen * fileheader.nCharSize;
                nStringBufferSize = AdjustBuffer(&lpStringBuffer, nStringBufferSize, nSourceSize, REGSHOT_BUFFER_BLOCK_BYTES);
                if (lpStringBuffer == NULL)
                    goto loadAllocationFailed;
                ZeroMemory(lpStringBuffer, nStringBufferSize);
                CopyMemory(lpStringBuffer, (lpFileBuffer + fileheader.ofsComputerName), nSourceSize);

                lpShot->lpszComputerName = MYALLOC(fileheader.nComputerNameLen * sizeof(TCHAR));
                if (lpShot->lpszComputerName == NULL)
                    goto loadAllocationFailed;
                if (fileextradata.bSameCharSize) {
                    _tcsncpy_s(lpShot->lpszComputerName, fileheader.nComputerNameLen, lpStringBuffer, fileheader.nComputerNameLen);
                }
                else {
#ifdef _UNICODE
                    MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, (LPCSTR)lpStringBuffer, -1, lpShot->lpszComputerName, fileheader.nComputerNameLen);
#else
                    WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK | WC_DEFAULTCHAR, (LPCWSTR)lpStringBuffer, -1, lpShot->lpszComputerName, fileheader.nComputerNameLen, NULL, NULL);
#endif
                }
                lpShot->lpszComputerName[fileheader.nComputerNameLen - 1] = (TCHAR)'\0';  // safety NULL char
            }
        }
        else {  // old SBCS/MBCS version
            // Copy string to an aligned memory block
            nSourceSize = strnlen((const char*)&fileheader.computername, OLD_COMPUTERNAMELEN);
            if (0 < nSourceSize) {  // otherwise leave it NULL
                nStringBufferSize = AdjustBuffer(&lpStringBuffer, nStringBufferSize, (nSourceSize + 1), REGSHOT_BUFFER_BLOCK_BYTES);
                if (lpStringBuffer == NULL)
                    goto loadAllocationFailed;
                ZeroMemory(lpStringBuffer, nStringBufferSize);
                CopyMemory(lpStringBuffer, &fileheader.computername, nSourceSize);

                lpShot->lpszComputerName = MYALLOC((nSourceSize + 1) * sizeof(TCHAR));
                if (lpShot->lpszComputerName == NULL)
                    goto loadAllocationFailed;
#ifdef _UNICODE
                MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, (LPCSTR)lpStringBuffer, (int)(nSourceSize + 1), lpShot->lpszComputerName, (int)(nSourceSize + 1));
#else
                strncpy(lpShot->lpszComputerName, lpStringBuffer, nSourceSize);
#endif
                lpShot->lpszComputerName[nSourceSize] = (TCHAR)'\0';  // safety NULL char
            }
        }

        // Copy user name from file header to shot data
        if (FILEHEADER_VERSION_1 < fileheader.nFHVersion) {  // newer Unicode/SBCS/MBCS version
            if (0 < fileheader.nUserNameLen) {  // otherwise leave it NULL
                // Copy string to an aligned memory block
                nSourceSize = fileheader.nUserNameLen * fileheader.nCharSize;
                nStringBufferSize = AdjustBuffer(&lpStringBuffer, nStringBufferSize, nSourceSize, REGSHOT_BUFFER_BLOCK_BYTES);
                if (lpStringBuffer == NULL)
                    goto loadAllocationFailed;
                ZeroMemory(lpStringBuffer, nStringBufferSize);
                CopyMemory(lpStringBuffer, (lpFileBuffer + fileheader.ofsUserName), nSourceSize);

                lpShot->lpszUserName = MYALLOC(fileheader.nUserNameLen * sizeof(TCHAR));
                if (lpShot->lpszUserName == NULL)
                    goto loadAllocationFailed;
                if (fileextradata.bSameCharSize) {
                    _tcsncpy_s(lpShot->lpszUserName, fileheader.nUserNameLen, lpStringBuffer, fileheader.nUserNameLen);
                }
                else {
#ifdef _UNICODE
                    MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, (LPCSTR)lpStringBuffer, -1, lpShot->lpszUserName, fileheader.nUserNameLen);
#else
                    WideCharToMultiByte(CP_ACP, WC_COMPOSITECHECK | WC_DEFAULTCHAR, (LPCWSTR)lpStringBuffer, -1, lpShot->lpszUserName, fileheader.nUserNameLen, NULL, NULL);
#endif
                }
                lpShot->lpszUserName[fileheader.nUserNameLen - 1] = (TCHAR)'\0';  // safety NULL char
            }
        }
        else {  // old SBCS/MBCS version
            // Copy string to an aligned memory block
            nSourceSize = strnlen((const char*)&fileheader.username, OLD_COMPUTERNAMELEN);
            if (0 < nSourceSize) {  // otherwise leave it NULL
                nStringBufferSize = AdjustBuffer(&lpStringBuffer, nStringBufferSize, (nSourceSize + 1), REGSHOT_BUFFER_BLOCK_BYTES);
                if (lpStringBuffer == NULL)
                    goto loadAllocationFailed;
                ZeroMemory(lpStringBuffer, nStringBufferSize);
                CopyMemory(lpStringBuffer, &fileheader.username, nSourceSize);

                lpShot->lpszUserName = MYALLOC((nSourceSize + 1) * sizeof(TCHAR));
                if (lpShot->lpszUserName == NULL)
                    goto loadAllocationFailed;
#ifdef _UNICODE
                MultiByteToWideChar(CP_ACP, MB_PRECOMPOSED, (LPCSTR)lpStringBuffer, (int)(nSourceSize + 1), lpShot->lpszUserName, (int)(nSourceSize + 1));
#else
                strncpy(lpShot->lpszUserName, lpStringBuffer, nSourceSize);
#endif
                lpShot->lpszUserName[nSourceSize] = (TCHAR)'\0';  // safety NULL char
            }
        }

        CopyMemory(&lpShot->systemtime, &fileheader.systemtime, sizeof(SYSTEMTIME));

        // Initialize save structures
        ZeroMemory(&sKC, sizeof(sKC));
        ZeroMemory(&sVC, sizeof(sVC));

        if (0 != fileheader.ofsHKLM) {
            LoadRegKeys(lpShot, fileheader.ofsHKLM, NULL, &lpShot->lpHKLM);
            if (lpShot->fIncomplete)
                goto loadAllocationFailed;

            // Update counters display (keys/values final)
            nCurrentTime = GetTickCount();
            UI_UpdateCounters(asLangTexts[iszTextKey].lpszText, asLangTexts[iszTextValue].lpszText, lpShot->stCounts.cKeys, lpShot->stCounts.cValues);
        }

        if (0 != fileheader.ofsHKU) {
            LoadRegKeys(lpShot, fileheader.ofsHKU, NULL, &lpShot->lpHKU);
            if (lpShot->fIncomplete)
                goto loadAllocationFailed;

            // Update counters display (keys/values final)
            nCurrentTime = GetTickCount();
            UI_UpdateCounters(asLangTexts[iszTextKey].lpszText, asLangTexts[iszTextValue].lpszText, lpShot->stCounts.cKeys, lpShot->stCounts.cValues);
        }

        if (0 != fileheader.ofsHF) {
            LoadHeadFiles(lpShot, fileheader.ofsHF, &lpShot->lpHF);
            if (lpShot->fIncomplete)
                goto loadAllocationFailed;

            // Update counters display (dirs/files final)
            nCurrentTime = GetTickCount();
            UI_UpdateCounters(asLangTexts[iszTextDir].lpszText, asLangTexts[iszTextFile].lpszText, lpShot->stCounts.cDirs, lpShot->stCounts.cFiles);
        }

        // Get total count of all items
        lpShot->stCounts.cAll = lpShot->stCounts.cKeys
            + lpShot->stCounts.cValues
            + lpShot->stCounts.cDirs
            + lpShot->stCounts.cFiles;

        FreeShot(originalShot);
        *originalShot = loadedShot;
        lpShot = originalShot;

        // Set GUI fields after loading...
        if (NULL != lpShot->lpHF) {
#ifdef _WINDOWS
            SendMessage(GetDlgItem(hWnd, IDC_CHECKDIR), BM_SETCHECK, (WPARAM)BST_CHECKED, (LPARAM)0);
            SendMessage(hWnd, WM_COMMAND, (WPARAM)IDC_CHECKDIR, (LPARAM)0);
#endif

            FindDirChain(lpShot->lpHF, lpszExtDir, EXTDIRLEN);  // Get new chains, must do this after loading! Length in TCHARs incl. NULL char
#ifdef _WINDOWS
            SetDlgItemText(hWnd, IDC_EDITDIR, lpszExtDir);
#endif
        }
        else {
#ifdef _WINDOWS
            SetDlgItemText(hWnd, IDC_EDITDIR, TEXT(""));
#endif
        }

        if (NULL != lpStringBuffer) {
            MYFREE(lpStringBuffer);
            lpStringBuffer = NULL;
        }

        if (NULL != lpFileBuffer) {
            MYFREE(lpFileBuffer);
            lpFileBuffer = NULL;
        }

        // Set flags
        lpShot->fFilled = TRUE;
        lpShot->fLoaded = TRUE;

        UI_ShowHideCounters(SW_HIDE);

        // overwrite first letter of file name with NULL character to get path only, then create backup for initialization on next call
        *(opfn.lpstrFile + opfn.nFileOffset) = 0x00;
        _tcscpy_s(lpszLastOpenDir, MAX_PATH, opfn.lpstrFile);

        return TRUE;

loadAllocationFailed:
        FreeShot(&loadedShot);
        if (lpStringBuffer != NULL) {
            MYFREE(lpStringBuffer);
            lpStringBuffer = NULL;
        }
        MYFREE(lpFileBuffer);
        lpFileBuffer = NULL;
        UI_ShowHideCounters(SW_HIDE);
        ErrMsg(TEXT("Not enough memory to load the snapshot. The previous shot was kept."));
        return FALSE;
    }


#ifdef _WINDOWS
    // ----------------------------------------------------------------------
    // Display details of shot in message box
    // ----------------------------------------------------------------------
    VOID DisplayShotInfo(HWND hDlg, LPREGSHOT lpShot)
    {
        LPTSTR lpszInfoBox;
        LPTSTR lpszComputerName;
        LPTSTR lpszUserName;
        LPTSTR lpszLoaded;
        LPTSTR lpszTitle;

        lpszComputerName = lpShot->lpszComputerName;
        if (NULL == lpszComputerName) {
            lpszComputerName = lpszEmpty;
        }
        lpszUserName = lpShot->lpszUserName;
        if (NULL == lpszUserName) {
            lpszUserName = lpszEmpty;
        }
        lpszLoaded = lpszEmpty;
        if (lpShot->fLoaded) {
            lpszLoaded = asLangTexts[iszTextLoadedFromFile].lpszText;
        }

        lpszInfoBox = MYALLOC0(SIZEOF_INFOBOX * sizeof(TCHAR));
        _sntprintf_s(lpszInfoBox, SIZEOF_INFOBOX, SIZEOF_INFOBOX, TEXT("%s %04d-%02d-%02d %02d:%02d:%02d\n%s %s\n%s %s\n%s %u\n%s %u\n%s %u\n%s %u\n%s %lu\n%s %lu\n%s\0"),
            asLangTexts[iszTextDateTime].lpszText,
            lpShot->systemtime.wYear, lpShot->systemtime.wMonth, lpShot->systemtime.wDay,
            lpShot->systemtime.wHour, lpShot->systemtime.wMinute, lpShot->systemtime.wSecond,
            asLangTexts[iszTextComputer].lpszText, lpszComputerName,
            asLangTexts[iszTextUsername].lpszText, lpszUserName,
            asLangTexts[iszTextKey].lpszText, lpShot->stCounts.cKeys,
            asLangTexts[iszTextValue].lpszText, lpShot->stCounts.cValues,
            asLangTexts[iszTextDir].lpszText, lpShot->stCounts.cDirs,
            asLangTexts[iszTextFile].lpszText, lpShot->stCounts.cFiles,
            asLangTexts[iszTextUnscannedDirs].lpszText, lpShot->cSkippedDirs,
            asLangTexts[iszTextUnscannedRegKeys].lpszText, lpShot->cSkippedRegKeys,
            lpszLoaded
        );
        lpszInfoBox[SIZEOF_INFOBOX - 1] = (TCHAR)'\0';  // safety NULL char

        lpszTitle = asLangTexts[iszTextMenuInfo].lpszText;
        if (&Shot1 == lpShot) {
            lpszTitle = asLangTexts[iszTextButtonShot1].lpszText;
        }
        else if (&Shot2 == lpShot) {
            lpszTitle = asLangTexts[iszTextButtonShot2].lpszText;
        }

        MessageBox(hDlg, lpszInfoBox, lpszTitle, MB_OK);
        MYFREE(lpszInfoBox);
    }
#endif


#ifdef _WINDOWS
    // ----------------------------------------------------------------------
    // Display details of comparison result in message box
    // ----------------------------------------------------------------------
    VOID DisplayResultInfo(HWND hDlg)
    {
        LPTSTR lpszInfoBox;
        LPTSTR lpszTitle;

        lpszInfoBox = MYALLOC0(SIZEOF_INFOBOX * sizeof(TCHAR));
        _sntprintf_s(lpszInfoBox, SIZEOF_INFOBOX, SIZEOF_INFOBOX, TEXT("%s %u\n%s %u\n%s %u\n%s %u\n%s %u\n%s %u\n%s %u\n%s %u\n%s %u\n%s %u\n%s %u\n%s %u\n\0"),
            asLangTexts[iszTextKeyDel].lpszText, CompareResult.stcDeleted.cKeys,
            asLangTexts[iszTextKeyAdd].lpszText, CompareResult.stcAdded.cKeys,
            asLangTexts[iszTextValDel].lpszText, CompareResult.stcDeleted.cValues,
            asLangTexts[iszTextValAdd].lpszText, CompareResult.stcAdded.cValues,
            asLangTexts[iszTextValModi].lpszText, CompareResult.stcModified.cValues,
            asLangTexts[iszTextDirDel].lpszText, CompareResult.stcDeleted.cDirs,
            asLangTexts[iszTextDirAdd].lpszText, CompareResult.stcAdded.cDirs,
            asLangTexts[iszTextDirModi].lpszText, CompareResult.stcModified.cDirs,
            asLangTexts[iszTextFileDel].lpszText, CompareResult.stcDeleted.cFiles,
            asLangTexts[iszTextFileAdd].lpszText, CompareResult.stcAdded.cFiles,
            asLangTexts[iszTextFileModi].lpszText, CompareResult.stcModified.cFiles,
            asLangTexts[iszTextTotal].lpszText, CompareResult.stcChanged.cAll
        );
        lpszInfoBox[SIZEOF_INFOBOX - 1] = (TCHAR)'\0';  // safety NULL char

        lpszTitle = asLangTexts[iszTextButtonCompare].lpszText;

        MessageBox(hDlg, lpszInfoBox, lpszTitle, MB_OK);
        MYFREE(lpszInfoBox);
    }
#endif


    // ----------------------------------------------------------------------
    // Swap shot 1 and shot 2
    // ----------------------------------------------------------------------
    VOID SwapShots(VOID)
    {
        REGSHOT ShotTemp;

        memcpy(&ShotTemp, &Shot1, sizeof(Shot1));     // backup Shot1 in ShotTemp
        memcpy(&Shot1, &Shot2, sizeof(Shot2));        // copy Shot2 to Shot1
        memcpy(&Shot2, &ShotTemp, sizeof(ShotTemp));  // copy ShotTemp (Shot1) to Shot2
    }


#ifdef _WINDOWS
    // ----------------------------------------------------------------------
    // Check if shot 1 and shot 2 are in chronological order, otherwise prompt to swap
    //   YES = swap, then proceed (returns TRUE)
    //   NO = no swap, then proceed (returns TRUE)
    //   CANCEL = no swap, then cancel functions (returns FALSE)
    // ----------------------------------------------------------------------
    BOOL CheckShotsChronology(HWND hDlg)
    {
        FILETIME ftime1;
        FILETIME ftime2;
        LPTSTR lpszChronoBox;
        LPTSTR lpszTitle;
        int nDialogAnswer;

        // CANCEL if not both shots filled
        if ((!Shot1.fFilled) || (!Shot2.fFilled)) {
            return FALSE;
        }

        // Compare time stamps of shots
        SystemTimeToFileTime(&(Shot1.systemtime), &ftime1);
        SystemTimeToFileTime(&(Shot2.systemtime), &ftime2);
        if (0 >= CompareFileTime(&ftime1, &ftime2)) {
            return TRUE;
        }

        // Define texts of message box  //TODO: I18N, create text indexes and translate
        lpszChronoBox = MYALLOC0(SIZEOF_CHRONOBOX * sizeof(TCHAR));
        _sntprintf_s(lpszChronoBox, SIZEOF_CHRONOBOX, SIZEOF_CHRONOBOX, TEXT("%s\n%s %s %04d-%02d-%02d %02d:%02d:%02d\n%s %s %04d-%02d-%02d %02d:%02d:%02d\n%s\n\0"),
            asLangTexts[iszTextShotsNotChronological].lpszText,
            asLangTexts[iszTextButtonShot1].lpszText, asLangTexts[iszTextDateTime].lpszText,
            Shot1.systemtime.wYear, Shot1.systemtime.wMonth, Shot1.systemtime.wDay,
            Shot1.systemtime.wHour, Shot1.systemtime.wMinute, Shot1.systemtime.wSecond,
            asLangTexts[iszTextButtonShot2].lpszText, asLangTexts[iszTextDateTime].lpszText,
            Shot2.systemtime.wYear, Shot2.systemtime.wMonth, Shot2.systemtime.wDay,
            Shot2.systemtime.wHour, Shot2.systemtime.wMinute, Shot2.systemtime.wSecond,
            asLangTexts[iszTextQuestionSwapShots].lpszText
        );
        lpszChronoBox[SIZEOF_CHRONOBOX - 1] = (TCHAR)'\0';  // safety NULL char

        lpszTitle = MYALLOC0(SIZEOF_CHRONOBOX * sizeof(TCHAR));
        _sntprintf_s(lpszTitle, SIZEOF_CHRONOBOX, SIZEOF_CHRONOBOX, TEXT("%s %s\0"),
            asLangTexts[iszTextChronology].lpszText,
            asLangTexts[iszTextWarning].lpszText
        );
        lpszTitle[SIZEOF_CHRONOBOX - 1] = (TCHAR)'\0';  // safety NULL char

        nDialogAnswer = MessageBox(hDlg, lpszChronoBox, lpszTitle, MB_ICONWARNING | MB_YESNOCANCEL | MB_DEFBUTTON2);
        if (IDCANCEL == nDialogAnswer) {
            return FALSE;
        }

        if (IDYES == nDialogAnswer) {
            SwapShots();
            cEnd = CompareResult.stcChanged.cAll;
            UI_InitProgressBar();
            FreeCompareResult();
            if (0 != cEnd) {
                nCurrentTime = GetTickCount();
                UI_UpdateProgressBar();
            }
            ClearRegKeyMatchFlags(Shot1.lpHKLM);
            ClearRegKeyMatchFlags(Shot2.lpHKLM);
            ClearRegKeyMatchFlags(Shot1.lpHKU);
            ClearRegKeyMatchFlags(Shot2.lpHKU);
            ClearHeadFileMatchFlags(Shot1.lpHF);
            ClearHeadFileMatchFlags(Shot2.lpHF);
            UI_ShowHideProgressBar(SW_HIDE);
        }

        return TRUE;
    }
#endif
