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
    void** frame;
    __try {
        frame = (void**)_AddressOfReturnAddress(); // RtlCaptureStackBackTrace and I are not the same

        MEMORY_BASIC_INFORMATION mbi;
        int i = 0;

        while (i < MAX_FRAMES && frame) {
            if (!VirtualQuery(frame, &mbi, sizeof(mbi)) || mbi.State != MEM_COMMIT)
                break;

            void* rip = *(frame + 1);
            if (!rip) break;

            if (i == 0 || hits[i - 1].Address != rip) {
                hits[i].Address = rip;
                hits[i++].Symbol = NULL;
            }

            void** next = (void**)(*frame);
            if (next <= frame || (BYTE*)next - (BYTE*)frame > 0x1000)
                break;

            frame = next;
        }

        *count = i;
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        *count = 0;
    }
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

__forceinline BOOL SKIsLikelyHook(const BYTE* p) {
    if (p[0] == 0xE9) return TRUE; // jmp rel32
    if (p[0] == 0xFF && ((p[1] & 0xF8) == 0x25 || (p[1] & 0x38) == 0x20)) return TRUE; // jmp [rip+imm] / jmp [mem]
    if (p[0] == 0x68 && p[5] == 0xC3) return TRUE; // push addr; ret
    if (p[0] == 0x48 && p[1] == 0xB8 && p[10] == 0xFF && (p[11] == 0xE0 || p[11] == 0xD0)) return TRUE; // movabs/jmp rax or call rax
    if (p[0] == 0x48 && p[1] == 0xB8 && (p[10] == 0xFF && (p[11] & 0xF8) == 0xD0)) return TRUE; // wider movabs+indirect check
    return FALSE;
}


__forceinline SIZE_T SKScanFunctionStub(const BYTE* src, BYTE* dst, size_t maxSize, BOOL* foundTerm) {
    SIZE_T copied = 0;
    *foundTerm = FALSE;

    while (copied < maxSize) {
        const BYTE* code = src + copied;
        BYTE* out = dst + copied;

        BYTE len = 0;
        BYTE op = code[0];

        while ((op & 0xFC) == 0x64 || (op & 0xF0) == 0xF0 ||
            (op & 0xFE) == 0x66 || (op & 0xF0) == 0x40) {
            op = code[++len];
        }

        op = code[len++];
        if (op == 0x0F) op = code[len++];

        BOOL ripFixup = FALSE;
        SIZE_T dispOffset = 0;
        INT32 origDisp = 0;

        if (!((op & 0xF0) == 0x90 || (op >= 0xB0 && op <= 0xBF))) {
            BYTE modrm = code[len++];
            BYTE mod = (modrm >> 6) & 0x3;
            BYTE rm = modrm & 0x7;

            if (mod == 0 && rm == 5) {
                ripFixup = TRUE;
                dispOffset = len;
                if (copied + len + 4 > maxSize) break;
                origDisp = *(INT32*)(code + len);
                len += 4;
            }
            else if (mod == 1) len += 1;
            else if (mod == 2) len += 4;
            if (rm == 4) len++;
        }

        switch (op) {
        case 0xE8: case 0xE9: case 0xA9:
        case 0x68: len += 4; break;
        case 0x6A: len += 1; break;
        default:
            if ((op & 0xF0) == 0x70 || op == 0xEB)
                len += 1;
            break;
        }

        if (len == 0 || copied + len > maxSize) break;
        memcpy(out, code, len);

        if (ripFixup) {
            UINT_PTR origRip = (UINT_PTR)(src + copied + len);
            UINT_PTR newRip = (UINT_PTR)(dst + copied + len);
            *(INT32*)(out + dispOffset) = (INT32)((origRip + origDisp) - newRip);
        }

        if (op == 0xC3 || op == 0xC2 || op == 0xCB || op == 0xCC) {
            copied += len;
            *foundTerm = TRUE;
            break;
        }

        if (op == 0x0F && code[1] == 0x05 && code[2] == 0xC3) {
            memcpy(out, code, 3);
            copied += 3;
            *foundTerm = TRUE;
            break;
        }

        copied += len;
    }

    return copied;
}

__forceinline void SKSafeCopyProxy(void* dst, const void* src, size_t maxSize) {
    BYTE* dstBytes = (BYTE*)dst;
    const BYTE* srcBytes = (const BYTE*)src;

    if (SKIsLikelyHook(srcBytes)) {
        dstBytes[0] = 0xC3;
        if (maxSize > 1)
            memset(dstBytes + 1, 0xCC, maxSize - 1);
        return;
    }

    SIZE_T copied = 0;
    BOOL terminated = FALSE;

    __try {
        copied = SKScanFunctionStub(srcBytes, dstBytes, maxSize, &terminated);
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        dstBytes[0] = 0xC3;
        copied = 1;
        terminated = TRUE;
    }

    if (!terminated) {
        dstBytes[0] = 0xC3;
        copied = 1;
    }

    if (copied < maxSize)
        memset(dstBytes + copied, 0xCC, maxSize - copied);
}

__forceinline void* SKProxyResolveHashed(DWORD hash, const void* func) {
    ULONGLONG now = __rdtsc();

    for (int i = 0; i < SK_TOTAL_SLOTS; ++i) {
        SK_PROXY_SLOT* slot = &gProxyTable[i];
        MemoryBarrier();

        if (slot->Hash == hash && slot->OriginalFunc == func && slot->InUse == 0) {
            slot->LastUsedTick = now;
            MemoryBarrier();
            return slot->TrampolineAddr;
        }
    }

    int index = SKFindFreeSlotFast();
    int pageIndex = index / SK_PROXYS_PER_PAGE;
    int offset = index % SK_PROXYS_PER_PAGE;
    SK_PROXY_SLOT* slot = &gProxyTable[index];

    if (InterlockedExchange(&slot->InUse, 1) != 0)
        return NULL;

    void* page = gProxyPages[pageIndex];
    if (!page) {
        void* newPage = VirtualAlloc(NULL, SK_PROXY_PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!newPage) {
            slot->InUse = 0;
            return NULL;
        }

        if (InterlockedCompareExchangePointer(&gProxyPages[pageIndex], newPage, NULL) != NULL) {
            VirtualFree(newPage, 0, MEM_RELEASE);
            page = gProxyPages[pageIndex];
        }
        else {
            page = newPage;
        }

        MemoryBarrier();
    }

    void* slotAddr = (BYTE*)page + offset * SK_PROXY_SLOT_SIZE;

    SKSafeCopyProxy(slotAddr, func, SK_PROXY_SLOT_SIZE);

    slot->Hash = hash;
    slot->OriginalFunc = (void*)func;
    slot->TrampolineAddr = slotAddr;
    slot->LastUsedTick = now;

    _ReadWriteBarrier();

    MemoryBarrier();
    slot->InUse = 0;

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
        SK_PROXY_SLOT* slot = &gProxyTable[i];

        if (slot->TrampolineAddr &&
            (now - slot->LastUsedTick > olderThan) &&
            InterlockedCompareExchange(&slot->InUse, 1, 0) == 0) {

            MemoryBarrier();

            SecureZeroMemory(slot->TrampolineAddr, SK_PROXY_SLOT_SIZE);
            slot->TrampolineAddr = NULL;
            slot->OriginalFunc = NULL;
            slot->LastUsedTick = 0;

            MemoryBarrier();

            slot->Hash = 0;

            slot->InUse = 0;
        }
    }
}

__forceinline BOOL SKIsFunc(const void* func, const void* base) {
    if (!func || !base) return TRUE;

    const IMAGE_DOS_HEADER* dos = (const IMAGE_DOS_HEADER*)base;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return TRUE;

    const IMAGE_NT_HEADERS* nt = (const IMAGE_NT_HEADERS*)((const BYTE*)base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return TRUE;

    const SIZE_T moduleSize = nt->OptionalHeader.SizeOfImage;
    const BYTE* moduleStart = (const BYTE*)base;
    const BYTE* moduleEnd = moduleStart + moduleSize;

    if ((const BYTE*)func < moduleStart || (const BYTE*)func >= moduleEnd)
        return TRUE;

    MEMORY_BASIC_INFORMATION mbi;
    if (!VirtualQuery(func, &mbi, sizeof(mbi)))
        return TRUE;

    DWORD protect = mbi.Protect & 0xFF;
    if (protect != PAGE_EXECUTE_READ && protect != PAGE_EXECUTE_READWRITE &&
        protect != PAGE_EXECUTE_WRITECOPY && protect != PAGE_EXECUTE)
        return TRUE;

    if (protect == PAGE_READWRITE || protect == PAGE_NOACCESS)
        return TRUE;

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

        const void* exportStart = (const BYTE*)base + dir->VirtualAddress;
        const void* exportEnd = (const BYTE*)exportStart + dir->Size;

        if ((BYTE*)resolved >= (BYTE*)exportStart && (BYTE*)resolved < (BYTE*)exportEnd) {
            const char* fwd = (const char*)resolved;

            const char* dot = strchr(fwd, '.');
            if (!dot) return NULL;

            char moduleName[64] = { 0 };
            char forwardApi[64] = { 0 };

            size_t modLen = dot - fwd;

            strncpy_s(moduleName, sizeof(moduleName), fwd, min(modLen, sizeof(moduleName) - 6));
            strcat_s(moduleName, sizeof(moduleName), ".dll");
            strncpy_s(forwardApi, sizeof(forwardApi), dot + 1, sizeof(forwardApi) - 1);

            void* forwardBase = SKGetModuleBase((const wchar_t*)moduleName);
            if (!forwardBase) return NULL;

            return SKGetProcedureAddrForCaller(forwardBase, forwardApi, flags);
        }

        if (SKIsFunc(resolved, base)) {
            void* stub = SKStepoverIfHooked(targetHash, resolved, base, flags);
            if (stub) return stub;
        }
        StackFrameHit hits[MAX_FRAMES];
        int count = 0;
        SKStackScan(hits, &count);
        for (int j = 0; j < count; ++j) {
            char msg[64];
        }

        return resolved;
    }

    return NULL;
}