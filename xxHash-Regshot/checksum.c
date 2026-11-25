/*
    Copyright 2026 Hackerslang

    This file is part of Regshot, distributed under the GNU Lesser
    General Public License, version 2.1 or later.
*/

#include "checksum.h"
#include "third_party/xxhash/xxh_x86dispatch.h"
#include <string.h>

#define SMALL_FILE_BUFFER_SIZE (16 * 1024)
#define FILE_BUFFER_SIZE (256 * 1024)

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

BOOL ChecksumFromFile(LPCTSTR filename, QWORD* checksum)
{
    unsigned char smallBuffer[SMALL_FILE_BUFFER_SIZE + 1];
    unsigned char* buffer = NULL;
    XXH3_state_t* state = NULL;
    HANDLE file;
    DWORD bytesRead, firstRead;
    BOOL success = FALSE;

    file = CreateFile(filename, GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return FALSE;
    }

    if (!InitOnceExecuteOnce(&dispatchOnce, InitializeHashDispatch, NULL, NULL)) {
        CloseHandle(file);
        return FALSE;
    }
    if (!ReadFile(file, smallBuffer, sizeof(smallBuffer), &firstRead, NULL))
        goto done;
    // A short synchronous disk-file read reaches EOF; no separate probe is needed.
    if (firstRead < sizeof(smallBuffer)) {
        *checksum = (QWORD)XXH3_64bits(smallBuffer, firstRead);
        success = TRUE;
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
        success = TRUE;
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
                success = TRUE;
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
    return success;
}
