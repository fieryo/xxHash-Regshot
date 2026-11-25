/*
    Copyright 2026 Hackerslang

    This file is part of Regshot, distributed under the GNU Lesser
    General Public License, version 2.1 or later.
*/

#include "checksum.h"
#include "third_party/xxhash/xxh_x86dispatch.h"
#include <string.h>
#include "text_extensions.h"

#define SMALL_FILE_BUFFER_SIZE (16 * 1024)
#define FILE_BUFFER_SIZE (256 * 1024)
#define TEXT_SAMPLE_SIZE 4096

BOOL IsKnownTextExtension(LPCTSTR filename)
{
    LPCTSTR name = filename, p, extension = NULL;
    size_t low = 0, high = sizeof(textExtensions) / sizeof(textExtensions[0]);

    for (p = filename; *p; ++p) {
        if (*p == (TCHAR)'\\' || *p == (TCHAR)'/') {
            name = p + 1;
            extension = NULL;
        }
        else if (*p == (TCHAR)'.') {
            extension = p + 1;
        }
    }
    if (extension == NULL || extension == name || *extension == 0)
        return FALSE;
    while (low < high) {
        size_t mid = low + (high - low) / 2;
        int cmp = _tcsicmp(extension, textExtensions[mid]);

        if (cmp == 0)
            return TRUE;
        if (cmp < 0)
            high = mid;
        else
            low = mid + 1;
    }
    return FALSE;
}

static BOOL LooksLikeText(const unsigned char* sample, DWORD size)
{
    DWORD i, evenZeros = 0, oddZeros = 0;

    if (size >= 4 && ((sample[0] == 0xff && sample[1] == 0xfe
        && sample[2] == 0 && sample[3] == 0)
        || (sample[0] == 0 && sample[1] == 0
            && sample[2] == 0xfe && sample[3] == 0xff)))
        return TRUE;
    if (size >= 2 && ((sample[0] == 0xff && sample[1] == 0xfe)
        || (sample[0] == 0xfe && sample[1] == 0xff)))
        return TRUE;
    for (i = 0; i < size; ++i) {
        unsigned char c = sample[i];

        if (c == 0) {
            if (i & 1)
                ++oddZeros;
            else
                ++evenZeros;
        }
        else if ((c < 0x20 && c != '\t' && c != '\n' && c != '\r' && c != '\f')
            || c == 0x7f)
            return FALSE;
    }
    if (evenZeros == 0 && oddZeros == 0)
        return TRUE;
    // BOM-less UTF-16 containing predominantly ASCII characters.
    return size >= 4 && ((oddZeros >= size / 4 && evenZeros == 0)
        || (evenZeros >= size / 4 && oddZeros == 0));
}

static INIT_ONCE dispatchOnce = INIT_ONCE_STATIC_INIT;

static BOOL CALLBACK InitializeHashDispatch(PINIT_ONCE once, PVOID parameter, PVOID* context)
{
    static const unsigned char input[256] = { 0 };
    (void)once;
    (void)parameter;
    (void)context;
    (void)XXH3_64bits_dispatch(input, sizeof(input));
    return TRUE;
}

static CHECKSUM_RESULT ChecksumFile(LPCTSTR filename, QWORD* checksum, BOOL textOnly)
{
    unsigned char smallBuffer[SMALL_FILE_BUFFER_SIZE + 1];
    unsigned char* buffer = NULL;
    XXH3_state_t* state = NULL;
    HANDLE file;
    DWORD bytesRead, firstRead, initialSize;
    CHECKSUM_RESULT result = CHECKSUM_ERROR;
    BOOL inspect = textOnly && !IsKnownTextExtension(filename);

    file = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return CHECKSUM_ERROR;
    }

    if (!InitOnceExecuteOnce(&dispatchOnce, InitializeHashDispatch, NULL, NULL)) {
        CloseHandle(file);
        return CHECKSUM_ERROR;
    }
    initialSize = inspect ? TEXT_SAMPLE_SIZE : sizeof(smallBuffer);
    if (!ReadFile(file, smallBuffer, initialSize, &firstRead, NULL))
        goto done;
    if (inspect && !LooksLikeText(smallBuffer, firstRead)) {
        result = CHECKSUM_NOT_TEXT;
        goto done;
    }
    if (inspect && firstRead == initialSize) {
        if (!ReadFile(file, smallBuffer + firstRead, sizeof(smallBuffer) - firstRead, &bytesRead, NULL))
            goto done;
        firstRead += bytesRead;
    }
    // A short synchronous disk-file read reaches EOF; no separate probe is needed.
    if (firstRead < sizeof(smallBuffer)) {
        *checksum = (QWORD)XXH3_64bits(smallBuffer, firstRead);
        result = CHECKSUM_OK;
        goto done;
    }

    buffer = HeapAlloc(GetProcessHeap(), 0, FILE_BUFFER_SIZE + 1);
    if (buffer == NULL) {
        SetLastError(ERROR_NOT_ENOUGH_MEMORY);
        goto done;
    }
    memcpy(buffer, smallBuffer, firstRead);
    if (!ReadFile(file, buffer + firstRead, FILE_BUFFER_SIZE + 1 - firstRead, &bytesRead, NULL))
        goto done;
    bytesRead += firstRead;
    if (bytesRead <= FILE_BUFFER_SIZE) {
        *checksum = (QWORD)XXH3_64bits(buffer, bytesRead);
        result = CHECKSUM_OK;
        goto done;
    }

    state = XXH3_createState();
    if (state == NULL)
        goto done;
    if (XXH3_64bits_reset(state) == XXH_OK
        && XXH3_64bits_update(state, buffer, bytesRead) == XXH_OK) {
        while (ReadFile(file, buffer, FILE_BUFFER_SIZE, &bytesRead, NULL)) {
            if (bytesRead == 0) {
                *checksum = (QWORD)XXH3_64bits_digest(state);
                result = CHECKSUM_OK;
                break;
            }
            if (XXH3_64bits_update(state, buffer, bytesRead) != XXH_OK) {
                break;
            }
        }
    }
done:
    if (state != NULL)
        XXH3_freeState(state);
    if (buffer != NULL)
        HeapFree(GetProcessHeap(), 0, buffer);
    CloseHandle(file);
    return result;
}

BOOL ChecksumFromFile(LPCTSTR filename, QWORD* checksum)
{
    return ChecksumFile(filename, checksum, FALSE) == CHECKSUM_OK;
}

CHECKSUM_RESULT ChecksumTextFile(LPCTSTR filename, QWORD* checksum)
{
    return ChecksumFile(filename, checksum, TRUE);
}
