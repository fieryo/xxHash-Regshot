#include "usnbaseline.h"
#include "third_party/xxhash/xxhash.h"
#include <stdlib.h>
#include <string.h>

#define USN_BASELINE_VERSION 1
#define USN_SET_USED 0x80

typedef struct {
    BYTE magic[8];
    DWORD version;
    DWORD headerSize;
    DWORD hashAlgorithm;
    DWORD volumeCount;
    DWORD entryCount;
    DWORD reserved;
    ULONGLONG payloadHash;
} USN_BASELINE_HEADER;

typedef char UsnBaselineHeaderSize[sizeof(USN_BASELINE_HEADER) == 40 ? 1 : -1];
typedef char UsnBaselineVolumeSize[sizeof(USN_BASELINE_VOLUME) == 152 ? 1 : -1];
typedef char UsnBaselineEntrySize[sizeof(USN_BASELINE_ENTRY) == 40 ? 1 : -1];

static const BYTE baselineMagic[8] = { 'R', 'S', 'U', 'S', 'N', 'B', 'L', 0 };

static size_t GuidLength(const WCHAR* guid)
{
    size_t i;

    for (i = 0; i < USN_BASELINE_GUID_CHARS; ++i)
        if (guid[i] == 0)
            return i;
    return USN_BASELINE_GUID_CHARS;
}

static BOOL GuidEqual(const WCHAR* left, const WCHAR* right)
{
    size_t i;

    for (i = 0; i < USN_BASELINE_GUID_CHARS; ++i) {
        if (left[i] != right[i])
            return FALSE;
        if (left[i] == 0)
            return TRUE;
    }
    return FALSE;
}

static BOOL ValidGuid(const WCHAR* guid)
{
    static const char prefix[] = "\\\\?\\Volume{";
    size_t i, length = GuidLength(guid);

    if (length >= USN_BASELINE_GUID_CHARS || length < sizeof(prefix))
        return FALSE;
    for (i = 0; i + 1 < sizeof(prefix); ++i)
        if (guid[i] != (WCHAR)prefix[i])
            return FALSE;
    return TRUE;
}

static int CompareEntries(const void* left, const void* right)
{
    const USN_BASELINE_ENTRY* a = left;
    const USN_BASELINE_ENTRY* b = right;

    if (a->volume != b->volume)
        return a->volume < b->volume ? -1 : 1;
    if (a->fileId != b->fileId)
        return a->fileId < b->fileId ? -1 : 1;
    return 0;
}

static BOOL SameEntry(const USN_BASELINE_ENTRY* a, const USN_BASELINE_ENTRY* b)
{
    return a->size == b->size && a->writeTime == b->writeTime
        && a->hash == b->hash && a->attributes == b->attributes;
}

static BOOL ValidBaseline(const USN_BASELINE* baseline)
{
    DWORD i, j;

    if (baseline->volumeCount > USN_BASELINE_MAX_VOLUMES
        || (baseline->volumeCount != 0 && baseline->volumes == NULL)
        || (baseline->entryCount != 0 && baseline->entries == NULL))
        return FALSE;
    for (i = 0; i < baseline->volumeCount; ++i) {
        if (!ValidGuid(baseline->volumes[i].volumeGuid)
            || baseline->volumes[i].checkpoint < 0)
            return FALSE;
        for (j = 0; j < i; ++j)
            if (GuidEqual(baseline->volumes[i].volumeGuid, baseline->volumes[j].volumeGuid))
                return FALSE;
    }
    for (i = 0; i < baseline->entryCount; ++i) {
        const USN_BASELINE_ENTRY* entry = &baseline->entries[i];

        if (entry->volume >= baseline->volumeCount || entry->fileId == 0
            || (i != 0 && CompareEntries(&baseline->entries[i - 1], entry) >= 0))
            return FALSE;
    }
    return TRUE;
}

BOOL UsnBaselineSerialize(const USN_BASELINE* baseline, BYTE** data, DWORD* size)
{
    USN_BASELINE_HEADER header;
    ULONGLONG total, volumeBytes, entryBytes;
    BYTE* buffer;

    if (baseline == NULL || data == NULL || size == NULL || !ValidBaseline(baseline))
        return FALSE;
    volumeBytes = (ULONGLONG)baseline->volumeCount * sizeof(USN_BASELINE_VOLUME);
    entryBytes = (ULONGLONG)baseline->entryCount * sizeof(USN_BASELINE_ENTRY);
    total = sizeof(header) + volumeBytes + entryBytes;
    if (total > 0x7fffffffULL)
        return FALSE;
    buffer = malloc((size_t)total);
    if (buffer == NULL)
        return FALSE;
    if (volumeBytes != 0)
        memcpy(buffer + sizeof(header), baseline->volumes, (size_t)volumeBytes);
    if (entryBytes != 0)
        memcpy(buffer + sizeof(header) + volumeBytes, baseline->entries, (size_t)entryBytes);
    memset(&header, 0, sizeof(header));
    memcpy(header.magic, baselineMagic, sizeof(baselineMagic));
    header.version = USN_BASELINE_VERSION;
    header.headerSize = sizeof(header);
    header.hashAlgorithm = USN_BASELINE_HASH_XXH3_64;
    header.volumeCount = baseline->volumeCount;
    header.entryCount = baseline->entryCount;
    header.payloadHash = XXH3_64bits(buffer + sizeof(header), (size_t)(total - sizeof(header)));
    memcpy(buffer, &header, sizeof(header));
    *data = buffer;
    *size = (DWORD)total;
    return TRUE;
}

BOOL UsnBaselineParse(const BYTE* data, DWORD size, USN_BASELINE* baseline)
{
    USN_BASELINE_HEADER header;
    USN_BASELINE result;
    ULONGLONG volumeBytes, entryBytes;

    if (baseline == NULL)
        return FALSE;
    memset(baseline, 0, sizeof(*baseline));
    if (data == NULL || size < sizeof(header))
        return FALSE;
    memcpy(&header, data, sizeof(header));
    if (memcmp(header.magic, baselineMagic, sizeof(baselineMagic)) != 0
        || header.version != USN_BASELINE_VERSION || header.headerSize != sizeof(header)
        || header.hashAlgorithm != USN_BASELINE_HASH_XXH3_64 || header.reserved != 0
        || header.volumeCount > USN_BASELINE_MAX_VOLUMES)
        return FALSE;
    volumeBytes = (ULONGLONG)header.volumeCount * sizeof(USN_BASELINE_VOLUME);
    entryBytes = (ULONGLONG)header.entryCount * sizeof(USN_BASELINE_ENTRY);
    if (sizeof(header) + volumeBytes + entryBytes != size
        || XXH3_64bits(data + sizeof(header), size - sizeof(header)) != header.payloadHash)
        return FALSE;

    memset(&result, 0, sizeof(result));
    result.volumeCount = header.volumeCount;
    result.entryCount = header.entryCount;
    if (volumeBytes != 0) {
        result.volumes = malloc((size_t)volumeBytes);
        if (result.volumes == NULL)
            return FALSE;
        memcpy(result.volumes, data + sizeof(header), (size_t)volumeBytes);
    }
    if (entryBytes != 0) {
        result.entries = malloc((size_t)entryBytes);
        if (result.entries == NULL) {
            UsnBaselineFree(&result);
            return FALSE;
        }
        memcpy(result.entries, data + sizeof(header) + volumeBytes, (size_t)entryBytes);
    }
    if (!ValidBaseline(&result)) {
        UsnBaselineFree(&result);
        return FALSE;
    }
    *baseline = result;
    return TRUE;
}

void UsnBaselineFree(USN_BASELINE* baseline)
{
    if (baseline == NULL)
        return;
    free(baseline->volumes);
    free(baseline->entries);
    memset(baseline, 0, sizeof(*baseline));
}

void UsnBaselineNormalizeEntries(USN_BASELINE_ENTRY* entries, DWORD* count)
{
    DWORD read = 0, write = 0;

    if (entries == NULL || count == NULL || *count == 0)
        return;
    qsort(entries, *count, sizeof(*entries), CompareEntries);
    while (read < *count) {
        DWORD end = read + 1;
        BOOL consistent = entries[read].fileId != 0;

        while (end < *count && CompareEntries(&entries[read], &entries[end]) == 0) {
            if (!SameEntry(&entries[read], &entries[end]))
                consistent = FALSE;
            ++end;
        }
        if (consistent)
            entries[write++] = entries[read];
        read = end;
    }
    *count = write;
}

const USN_BASELINE_ENTRY* UsnBaselineFind(const USN_BASELINE* baseline,
    DWORD volume, ULONGLONG fileId)
{
    USN_BASELINE_ENTRY key;

    if (baseline == NULL || baseline->entryCount == 0)
        return NULL;
    memset(&key, 0, sizeof(key));
    key.volume = volume;
    key.fileId = fileId;
    return bsearch(&key, baseline->entries, baseline->entryCount,
        sizeof(key), CompareEntries);
}

int UsnBaselineFindVolume(const USN_BASELINE* baseline, const WCHAR* volumeGuid,
    DWORD volumeSerial, ULONGLONG journalId)
{
    DWORD i;

    if (baseline == NULL || volumeGuid == NULL)
        return -1;
    for (i = 0; i < baseline->volumeCount; ++i) {
        const USN_BASELINE_VOLUME* volume = &baseline->volumes[i];

        if (GuidEqual(volume->volumeGuid, volumeGuid))
            return volume->volumeSerial == volumeSerial && volume->journalId == journalId
                ? (int)i : -1;
    }
    return -1;
}

static DWORD Slot(ULONGLONG fileId, DWORD capacity)
{
    return (DWORD)((fileId * 0x9E3779B97F4A7C15ULL) >> 32) & (capacity - 1);
}

static BOOL Grow(USN_CHANGE_SET* set)
{
    USN_CHANGE_SET grown;
    DWORD i;

    grown.capacity = set->capacity == 0 ? 1024 : set->capacity * 2;
    if (grown.capacity < set->capacity)
        return FALSE;
    grown.count = 0;
    grown.keys = malloc(grown.capacity * sizeof(*grown.keys));
    grown.flags = calloc(grown.capacity, sizeof(*grown.flags));
    if (grown.keys == NULL || grown.flags == NULL) {
        free(grown.keys);
        free(grown.flags);
        return FALSE;
    }
    for (i = 0; i < set->capacity; ++i) {
        if (set->flags[i] & USN_SET_USED) {
            DWORD slot = Slot(set->keys[i], grown.capacity);

            while (grown.flags[slot] & USN_SET_USED)
                slot = (slot + 1) & (grown.capacity - 1);
            grown.keys[slot] = set->keys[i];
            grown.flags[slot] = set->flags[i];
            ++grown.count;
        }
    }
    UsnChangeSetFree(set);
    *set = grown;
    return TRUE;
}

BOOL UsnChangeSetAdd(USN_CHANGE_SET* set, ULONGLONG fileId, BOOL changed, BOOL closed)
{
    DWORD slot;

    if (set == NULL)
        return FALSE;
    if ((set->count + 1) * 2 > set->capacity && !Grow(set))
        return FALSE;
    slot = Slot(fileId, set->capacity);
    while ((set->flags[slot] & USN_SET_USED) && set->keys[slot] != fileId)
        slot = (slot + 1) & (set->capacity - 1);
    if (!(set->flags[slot] & USN_SET_USED)) {
        set->keys[slot] = fileId;
        set->flags[slot] = USN_SET_USED;
        ++set->count;
    }
    if (changed)
        set->flags[slot] |= USN_FILE_CHANGED;
    if (closed)
        set->flags[slot] &= (BYTE)~USN_FILE_OPEN;
    else
        set->flags[slot] |= USN_FILE_OPEN;
    return TRUE;
}

DWORD UsnChangeSetFlags(const USN_CHANGE_SET* set, ULONGLONG fileId)
{
    DWORD slot;

    if (set == NULL || set->capacity == 0)
        return 0;
    slot = Slot(fileId, set->capacity);
    while (set->flags[slot] & USN_SET_USED) {
        if (set->keys[slot] == fileId)
            return set->flags[slot] & (USN_FILE_CHANGED | USN_FILE_OPEN);
        slot = (slot + 1) & (set->capacity - 1);
    }
    return 0;
}

void UsnChangeSetFree(USN_CHANGE_SET* set)
{
    if (set == NULL)
        return;
    free(set->keys);
    free(set->flags);
    memset(set, 0, sizeof(*set));
}

BOOL UsnCanCacheHash(ULONGLONG fileId, DWORD changeFlags, DWORD attributes)
{
    return fileId != 0 && !(changeFlags & USN_FILE_OPEN)
        && !(attributes & (FILE_ATTRIBUTE_DIRECTORY | FILE_ATTRIBUTE_REPARSE_POINT));
}

BOOL UsnCanReuseHash(const USN_BASELINE_ENTRY* entry, DWORD changeFlags,
    ULONGLONG size, ULONGLONG writeTime, DWORD attributes)
{
    return entry != NULL && !(changeFlags & USN_FILE_CHANGED)
        && UsnCanCacheHash(entry->fileId, changeFlags, attributes)
        && entry->size == size && entry->writeTime == writeTime
        && entry->attributes == attributes;
}
