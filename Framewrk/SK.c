#include "SK.h"

void* gProxyPages[SK_PROXY_PAGE_COUNT] = { 0 };
SK_PROXY_SLOT gProxyTable[SK_TOTAL_SLOTS] = { 0 };
volatile LONG gProxySlotCounter = 0;

__forceinline DWORD __fastcall SKHash(const char* str) {
    DWORD hash = 0x811C9DC5;
    DWORD key = 0xA3B376C9;
    char c;

    while ((c = *str++)) {
        c |= 0x20;
        c ^= (char)key;
        hash ^= c;
        hash *= 0x01000193;
        key = _rotl(key ^ c, 5);
    }

    hash ^= hash >> 13;
    hash *= 0x5bd1e995;
    hash ^= hash >> 15;

    return hash;
}

void SKStackScan(StackFrameHit* hits, int* count) {
    void** frame = (void**)_AddressOfReturnAddress();
    int i = 0;

    __try {
        while (i < MAX_FRAMES && frame) {
            void* rip = *(frame + 1);
            if (!rip) break;

            if (i == 0 || hits[i - 1].Address != rip) {
                hits[i].Address = rip;
                hits[i++].Symbol = NULL;
            }

            frame = (void**)(*frame);
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        // rofl 
    }

    *count = i;
}

__forceinline BOOL SKIsLikelyHook(const BYTE* p) {
    if (p[0] == 0xE9) return TRUE;                            // JMP rel32
    if (p[0] == 0xFF && (p[1] & 0xF8) == 0x25) return TRUE;   // JMP [rip+imm]
    if (p[0] == 0x68 && p[5] == 0xC3) return TRUE;            // PUSH addr + RET
    return FALSE;
}

__forceinline int SKFindFreeSlotFast() {
    int start = InterlockedCompareExchange(&gProxySlotCounter, 0, 0);

    for (int i = 0; i < SK_TOTAL_SLOTS; ++i) {
        int idx = (start + i) % SK_TOTAL_SLOTS;
        if (!gProxyTable[idx].TrampolineAddr)
            return idx;
    }

    return InterlockedIncrement(&gProxySlotCounter) % SK_TOTAL_SLOTS;
}

__forceinline void SKSafeCopyProxy(void* dst, const void* src, size_t size) {
    const BYTE* srcBytes = (const BYTE*)src;
    BYTE* dstBytes = (BYTE*)dst;

    if (SKIsLikelyHook(srcBytes)) {
        dstBytes[0] = 0xC3;
        memset(dstBytes + 1, 0xCC, size - 1);
    }
    else {
        memcpy(dstBytes, srcBytes, size);
    }
}

__forceinline void* SKProxyResolveHashed(DWORD hash, const void* func) {
    ULONGLONG now = __rdtsc();

    for (int i = 0; i < SK_TOTAL_SLOTS; ++i) {
        if (gProxyTable[i].Hash == hash) {
            gProxyTable[i].LastUsedTick = now;
            return gProxyTable[i].TrampolineAddr;
        }
    }

    int index = SKFindFreeSlotFast();
    int pageIndex = index / SK_PROXYS_PER_PAGE;
    int offset = index % SK_PROXYS_PER_PAGE;

    if (!gProxyPages[pageIndex]) {
        void* newPage = VirtualAlloc(NULL, SK_PROXY_PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!newPage) return NULL;

        if (InterlockedCompareExchangePointer(&gProxyPages[pageIndex], newPage, NULL) != NULL)
            VirtualFree(newPage, 0, MEM_RELEASE);
    }

    void* page = gProxyPages[pageIndex];
    void* slotAddr = (BYTE*)page + offset * SK_PROXY_SLOT_SIZE;

    SKSafeCopyProxy(slotAddr, func, SK_PROXY_SLOT_SIZE);

    gProxyTable[index].Hash = hash;
    gProxyTable[index].OriginalFunc = (void*)func;
    gProxyTable[index].TrampolineAddr = slotAddr;
    gProxyTable[index].LastUsedTick = now;

    return slotAddr;
}

__forceinline void* SKStepoverIfHooked(DWORD hash, const void* func, const void* base, DWORD flags) {
    const IMAGE_NT_HEADERS* nt = (const IMAGE_NT_HEADERS*)((const BYTE*)base + ((const IMAGE_DOS_HEADER*)base)->e_lfanew);
    const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (memcmp(sec->Name, ".text", 5) == 0) {
            const BYTE* start = (const BYTE*)base + sec->VirtualAddress;
            const BYTE* end = start + sec->Misc.VirtualSize;

            if ((const BYTE*)func < start || (const BYTE*)func > end)
                return NULL;

            void* trampoline = SKProxyResolveHashed(hash, func);
            if (!trampoline) return NULL;

#if defined(_DEBUG)
            if (flags & SK_FLAG_ENABLE_SEH) {
                __try {
                    RaiseException(SK_EXCEPTION_HOOK_DETECTED, 0, 0, NULL);
                }
                __except (GetExceptionCode() == SK_EXCEPTION_HOOK_DETECTED
                    ? EXCEPTION_EXECUTE_HANDLER
                    : EXCEPTION_CONTINUE_SEARCH) {
                }
            }
#endif

            return trampoline;
        }
    }

    return NULL;
}

void SKProxyLRU(ULONGLONG olderThan) {
    ULONGLONG now = __rdtsc();
    for (int i = 0; i < SK_TOTAL_SLOTS; ++i) {
        if (gProxyTable[i].TrampolineAddr &&
            (now - gProxyTable[i].LastUsedTick) > olderThan) {

            SecureZeroMemory(gProxyTable[i].TrampolineAddr, SK_PROXY_SLOT_SIZE);

            gProxyTable[i].Hash = 0;
            gProxyTable[i].OriginalFunc = NULL;
            gProxyTable[i].TrampolineAddr = NULL;
            gProxyTable[i].LastUsedTick = 0;
        }
    }
}

__forceinline BOOL SKIsFuncOutOfTextSect(const void* func, const void* base) {
    const IMAGE_NT_HEADERS* nt = (const IMAGE_NT_HEADERS*)((const BYTE*)base + ((const IMAGE_DOS_HEADER*)base)->e_lfanew);
    const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (memcmp(sec->Name, ".text", 5) == 0) {
            const BYTE* start = (const BYTE*)base + sec->VirtualAddress;
            const BYTE* end = start + sec->Misc.VirtualSize;
            return (const BYTE*)func < start || (const BYTE*)func > end;
        }
    }

    return FALSE;
}

void* SKGetModuleBase(const wchar_t* name) {
    const PEB* peb = (PEB*)__readgsqword(0x60);
    const LIST_ENTRY* list = &peb->Ldr->InMemoryOrderModuleList;

    for (const LIST_ENTRY* curr = list->Flink; curr != list; curr = curr->Flink) {
        const LDR_DATA_TABLE_ENTRY* entry = (const LDR_DATA_TABLE_ENTRY*)((const BYTE*)curr - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));
        if (!_wcsicmp(entry->BaseDllName.Buffer, name))
            return entry->DllBase;
    }

    return NULL;
}

void* SKGetProcedureAddrForCaller(const void* base, const char* funcName, DWORD flags) {
    DWORD targetHash = SKHash(funcName);

    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)base;
    const IMAGE_NT_HEADERS* nt = (const IMAGE_NT_HEADERS*)((const BYTE*)base + dos->e_lfanew);
    const IMAGE_DATA_DIRECTORY* dir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (!dir->VirtualAddress) return NULL;

    const IMAGE_EXPORT_DIRECTORY* exp = (const IMAGE_EXPORT_DIRECTORY*)((const BYTE*)base + dir->VirtualAddress);
    const DWORD* names = (const DWORD*)((const BYTE*)base + exp->AddressOfNames);
    const DWORD* funcs = (const DWORD*)((const BYTE*)base + exp->AddressOfFunctions);
    const WORD* ords = (const WORD*)((const BYTE*)base + exp->AddressOfNameOrdinals);

    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        const char* name = (const char*)base + names[i];
        if (SKHash(name) != targetHash) continue;

        void* resolved = (BYTE*)base + funcs[ords[i]];

        if (SKIsFuncOutOfTextSect(resolved, base)) {
            void* stub = SKStepoverIfHooked(targetHash, resolved, base, flags);
            if (stub) return stub;
        }

#if defined(_DEBUG)
        StackFrameHit hits[MAX_FRAMES];
        int count = 0;
        SKStackScan(hits, &count);
        for (int j = 0; j < count; ++j) {
            char msg[64];
            sprintf_s(msg, sizeof(msg), "[SK] return frame @ %p\n", hits[j].Address);
            OutputDebugStringA(msg);
        }
#endif

        return resolved;
    }

    return NULL;
}