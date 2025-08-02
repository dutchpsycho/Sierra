/*
 * ==================================================================================
 *  Repository:   Sierra Framework
 *  Project:      Sierra
 *  File:         sierra.c
 *  Author:       DutchPsycho
 *  Organization: TITAN Softwork Solutions
 *
 *  Description:
 *      SIERRA runtime control-flow redirection framework for x64 usermode.
 *      Built for environments with patched, forwarded, or inline-hooked APIs.
 *
 *  License:      Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)
 *  Copyright:    (C) 2025 TITAN Softwork Solutions. All rights reserved.
 *
 *  Licensing Terms:
 *  ----------------------------------------------------------------------------------
 *   - You are free to use, modify, and share this software.
 *   - Commercial use is strictly prohibited.
 *   - Proper credit must be given to TITAN Softwork Solutions.
 *   - Modifications must be clearly documented.
 *   - This software is provided "as-is" without warranties of any kind.
 *
 *  Full License: https://creativecommons.org/licenses/by-nc/4.0/
 * ==================================================================================
 */

#include "sierra.h"

void* gProxyPages[SR_PROXY_PAGE_COUNT] = { 0 };
SR_PROXY_SLOT gProxyTable[SR_TOTAL_SLOTS] = { 0 };
SIERRA_HOOK gHookTable[SIERRA_MAX_HOOKS] = { 0 };
volatile LONG gProxySlotCounter = 0;

__forceinline DWORD __fastcall SRHash(const char* str) {
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

void SRStackScan(StackFrameHit* hits, int* count) {
    void** frame;
    MEMORY_BASIC_INFORMATION mbi;
    int i = 0;

    __try {
        frame = (void**)_AddressOfReturnAddress();

        while (i < MAX_FRAMES && frame) {
            if (!VirtualQuery(frame, &mbi, sizeof(mbi)) ||
                mbi.State != MEM_COMMIT ||
                !(mbi.Protect & (PAGE_READWRITE | PAGE_EXECUTE_READWRITE)))
                break;

            if ((BYTE*)frame < (BYTE*)mbi.BaseAddress ||
                (BYTE*)frame >= ((BYTE*)mbi.BaseAddress + mbi.RegionSize))
                break;

            void* rip = *(frame + 1);
            if (!rip || !VirtualQuery(rip, &mbi, sizeof(mbi)) ||
                mbi.State != MEM_COMMIT ||
                !(mbi.Protect & (PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE)))
                break;

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

__forceinline int SRFindFreeSlotFast() {
    int start = InterlockedCompareExchange(&gProxySlotCounter, 0, 0);

    for (int i = 0; i < SR_TOTAL_SLOTS; ++i) {
        int idx = (start + i) % SR_TOTAL_SLOTS;
        if (!gProxyTable[idx].TrampolineAddr)
            return idx;
    }

    return InterlockedIncrement(&gProxySlotCounter) % SR_TOTAL_SLOTS;
}

__forceinline BOOL SRIsLikelyHook(const BYTE* p) {
    if (p[0] == 0xE9) return TRUE; // jmp rel32
    if (p[0] == 0xFF && ((p[1] & 0xF8) == 0x25 || (p[1] & 0x38) == 0x20)) return TRUE; // jmp [rip+imm] / jmp [mem]
    if (p[0] == 0x68 && p[5] == 0xC3) return TRUE; // push addr; ret
    if (p[0] == 0x48 && p[1] == 0xB8 && p[10] == 0xFF && (p[11] == 0xE0 || p[11] == 0xD0)) return TRUE; // movabs/jmp rax or call rax
    if (p[0] == 0x48 && p[1] == 0xB8 && (p[10] == 0xFF && (p[11] & 0xF8) == 0xD0)) return TRUE; // wider movabs+indirect check
    return FALSE;
}

__forceinline SIZE_T SRScanFunctionStub(const BYTE* src, BYTE* dst, size_t maxSize, BOOL* foundTerm) {
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

__forceinline void SRSafeCopyProxy(void* dst, const void* src, size_t maxSize) {
    BYTE* dstBytes = (BYTE*)dst;
    const BYTE* srcBytes = (const BYTE*)src;

    if (SRIsLikelyHook(srcBytes)) {
        dstBytes[0] = 0xC3;
        if (maxSize > 1)
            memset(dstBytes + 1, 0xCC, maxSize - 1);
        return;
    }

    SIZE_T copied = 0;
    BOOL terminated = FALSE;

    __try {
        copied = SRScanFunctionStub(srcBytes, dstBytes, maxSize, &terminated);
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

__forceinline void* SRProxyResolveHashed(DWORD hash, const void* func) {
    ULONGLONG now = __rdtsc();

    for (int i = 0; i < SR_TOTAL_SLOTS; ++i) {
        SR_PROXY_SLOT* slot = &gProxyTable[i];
        if (slot->Hash == hash && slot->OriginalFunc == func) {
            slot->LastUsedTick = now;
            return slot->TrampolineAddr;
        }
    }

    int index = SRFindFreeSlotFast();
    int pageIndex = index / SR_PROXYS_PER_PAGE;
    int offset = index % SR_PROXYS_PER_PAGE;
    SR_PROXY_SLOT* slot = &gProxyTable[index];

    int spin = 0;
    for (int spin = 0; InterlockedCompareExchange(&slot->InUse, 1, 0) != 0; ++spin) {
        _mm_pause();
        if (spin > 64) {
            Sleep(0);
            spin = 0;
        }
    }

    void* page = gProxyPages[pageIndex];
    if (!page) {
        void* newPage = VirtualAlloc(NULL, SR_PROXY_PAGE_SIZE, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!newPage) {
            InterlockedExchange(&slot->InUse, 0);
            return NULL;
        }

        if (InterlockedCompareExchangePointer(&gProxyPages[pageIndex], newPage, NULL) != NULL) {
            VirtualFree(newPage, 0, MEM_RELEASE);
            page = gProxyPages[pageIndex];
        }
        else {
            page = newPage;
        }
    }

    void* slotAddr = (BYTE*)page + offset * SR_PROXY_SLOT_SIZE;
    SRSafeCopyProxy(slotAddr, func, SR_PROXY_SLOT_SIZE);

    slot->Hash = hash;
    slot->OriginalFunc = (void*)func;
    slot->TrampolineAddr = slotAddr;
    slot->LastUsedTick = now;

    InterlockedExchange(&slot->InUse, 0);

    return slotAddr;
}

__forceinline void* SRStepoverIfHooked(DWORD hash, const void* func, const void* base, DWORD flags) {
    const IMAGE_NT_HEADERS* nt = (const IMAGE_NT_HEADERS*)((const BYTE*)base + ((const IMAGE_DOS_HEADER*)base)->e_lfanew);

    const IMAGE_DATA_DIRECTORY* expDir = &nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (expDir->VirtualAddress && expDir->Size) {
        const BYTE* expStart = (const BYTE*)base + expDir->VirtualAddress;
        const BYTE* expEnd = expStart + expDir->Size;

        if ((const BYTE*)func >= expStart && (const BYTE*)func < expEnd) {
            // exported RVA points back inside .edata — likely forwarded/redirected hook
            return NULL;
        }
    }

    const IMAGE_SECTION_HEADER* sec = IMAGE_FIRST_SECTION(nt);

    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; ++i, ++sec) {
        if (memcmp(sec->Name, ".text", 5) == 0) {
            const BYTE* start = (const BYTE*)base + sec->VirtualAddress;
            const BYTE* end = start + sec->Misc.VirtualSize;

            if ((const BYTE*)func < start || (const BYTE*)func > end)
                return NULL;

            void* trampoline = SRProxyResolveHashed(hash, func);
            if (!trampoline) return NULL;

#if defined(_DEBUG)
            if (flags & SR_FLAG_ENABLE_SEH) {
                __try {
                    RaiseException(SR_EXCEPTION_HOOK_DETECTED, 0, 0, NULL);
                }
                __except (GetExceptionCode() == SR_EXCEPTION_HOOK_DETECTED
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

void SRProxyLRU(ULONGLONG olderThan) {
    ULONGLONG now = __rdtsc();

    for (int i = 0; i < SR_TOTAL_SLOTS; ++i) {
        SR_PROXY_SLOT* slot = &gProxyTable[i];

        if (slot->TrampolineAddr &&
            (now - slot->LastUsedTick > olderThan) &&
            InterlockedCompareExchange(&slot->InUse, 1, 0) == 0) {

            MemoryBarrier();

            SecureZeroMemory(slot->TrampolineAddr, SR_PROXY_SLOT_SIZE);
            slot->TrampolineAddr = NULL;
            slot->OriginalFunc = NULL;
            slot->LastUsedTick = 0;

            MemoryBarrier();

            slot->Hash = 0;

            slot->InUse = 0;
        }
    }
}

__forceinline BOOL SRIsFunc(const void* func, const void* base) {
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

__forceinline void* SRGetModuleBase(const wchar_t* name) {
    static struct { const wchar_t* modName; void* base; } cMod[16] = { 0 };

    for (int i = 0; i < 16; ++i) {
        if (cMod[i].modName && !_wcsicmp(cMod[i].modName, name))
            return cMod[i].base;
    }

    const PEB* peb = (PEB*)__readgsqword(0x60);
    const LIST_ENTRY* list = &peb->Ldr->InMemoryOrderModuleList;

    for (const LIST_ENTRY* curr = list->Flink; curr != list; curr = curr->Flink) {
        const LDR_DATA_TABLE_ENTRY* entry = (const LDR_DATA_TABLE_ENTRY*)((const BYTE*)curr - offsetof(LDR_DATA_TABLE_ENTRY, InMemoryOrderLinks));
        if (!_wcsicmp(entry->BaseDllName.Buffer, name)) {
            for (int j = 0; j < 16; ++j) {
                if (!cMod[j].modName) {
                    cMod[j].modName = entry->BaseDllName.Buffer;
                    cMod[j].base = entry->DllBase;
                    break;
                }
            }
            return entry->DllBase;
        }
    }

    return NULL;
}

void* SRGetProcedureAddrForCaller(const void* base, const char* funcName, DWORD flags) {
    DWORD targetHash = SRHash(funcName);

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
        if (SRHash(name) != targetHash) continue;

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

            void* forwardBase = SRGetModuleBase((const wchar_t*)moduleName);
            if (!forwardBase) return NULL;

            return SRGetProcedureAddrForCaller(forwardBase, forwardApi, flags);
        }

        if (SRIsFunc(resolved, base)) {
            void* stub = SRStepoverIfHooked(targetHash, resolved, base, flags);
            if (stub) return stub;
        }
        StackFrameHit hits[MAX_FRAMES];
        int count = 0;
        SRStackScan(hits, &count);
        for (int j = 0; j < count; ++j) {
            char msg[64];
        }

        return resolved;
    }

    return NULL;
}

UINT_PTR PageAlignDown(UINT_PTR addr, SIZE_T pageSize) {
    return addr & ~(pageSize - 1);
}

UINT_PTR PageAlignUp(UINT_PTR addr, SIZE_T len, SIZE_T pageSize) {
    UINT_PTR end = addr + len - 1;
    return (end & ~(pageSize - 1)) + pageSize;
}

BOOL SRpEngine(void* handler, BYTE* outPatch, SIZE_T* outLen) {
    if (!handler || !outPatch || !outLen) return FALSE;

    // patch templates
    const int mode = rand() % 4;

    switch (mode) {
    case 0: {
        // push rax ; mov rax, handler ; xchg [rsp], rax ; ret
        outPatch[0] = 0x50;             // push rax
        outPatch[1] = 0x48;
        outPatch[2] = 0xB8;             // mov rax, imm64
        *(void**)(&outPatch[3]) = handler;
        outPatch[11] = 0x48;
        outPatch[12] = 0x87;
        outPatch[13] = 0x04;
        outPatch[14] = 0x24;            // xchg [rsp], rax
        outPatch[15] = 0xC3;            // ret
        *outLen = 16;
        break;
    }

    case 1: {
        // mov rax, handler ; push rax ; ret
        outPatch[0] = 0x48;
        outPatch[1] = 0xB8;
        *(void**)(&outPatch[2]) = handler;
        outPatch[10] = 0x50;            // push rax
        outPatch[11] = 0xC3;            // ret
        *outLen = 12;
        break;
    }

    case 2: {
        // push handler (imm64) ; ret
        outPatch[0] = 0x68;                         // push imm32 (low)
        *(DWORD*)&outPatch[1] = (DWORD)(uintptr_t)handler;

        outPatch[5] = 0xC7;                         // mov [rsp+4], high
        outPatch[6] = 0x44;
        outPatch[7] = 0x24;
        outPatch[8] = 0x04;
        *(DWORD*)&outPatch[9] = ((uintptr_t)handler) >> 32;

        outPatch[13] = 0xC3;                        // ret
        *outLen = 14;
        break;
    }

    case 3: {
        // pushfq ; mov rax, handler ; xchg [rsp], rax ; popfq ; ret
        outPatch[0] = 0x9C;                         // pushfq
        outPatch[1] = 0x48;
        outPatch[2] = 0xB8;
        *(void**)(&outPatch[3]) = handler;
        outPatch[11] = 0x48;
        outPatch[12] = 0x87;
        outPatch[13] = 0x04;
        outPatch[14] = 0x24;
        outPatch[15] = 0x9D;                        // popfq
        outPatch[16] = 0xC3;
        *outLen = 17;
        break;
    }

    default:
        return FALSE;
    }

    return TRUE;
}

BOOL SRIntercept(void* targetFunc,
    void* handler,
    BYTE* originalOut,
    SIZE_T* lengthOut)
{
    if (!targetFunc || !handler || !originalOut || !lengthOut)
        return FALSE;

    BYTE patch[32];
    SIZE_T patchLen = 0;
    if (!SRpEngine(handler, patch, &patchLen))
        return FALSE;

    memcpy(originalOut, targetFunc, patchLen);
    *lengthOut = patchLen;

    SYSTEM_INFO si; GetSystemInfo(&si);
    SIZE_T pageSize = si.dwPageSize;
    UINT_PTR addr = (UINT_PTR)targetFunc;
    UINT_PTR regionStart = PageAlignDown(addr, pageSize);
    UINT_PTR regionEnd = PageAlignUp(addr, patchLen, pageSize);
    SIZE_T regionSize = regionEnd - regionStart;

    DWORD oldProtect;
    if (!VirtualProtect((LPVOID)regionStart, regionSize, PAGE_EXECUTE_READWRITE, &oldProtect))
        return FALSE;

    memcpy((void*)addr, patch, patchLen);

    FlushInstructionCache(GetCurrentProcess(), (LPCVOID)addr, patchLen);

    DWORD tmp;
    VirtualProtect((LPVOID)regionStart, regionSize, oldProtect, &tmp);

    return TRUE;
}

BOOL SRRestore(void* targetFunc, const BYTE* original, SIZE_T len)
{
    if (!targetFunc || !original || len == 0)
        return FALSE;

    // compute same aligned region
    SYSTEM_INFO si; GetSystemInfo(&si);
    SIZE_T pageSize = si.dwPageSize;
    UINT_PTR addr = (UINT_PTR)targetFunc;
    UINT_PTR start = PageAlignDown(addr, pageSize);
    UINT_PTR end = PageAlignUp(addr, len, pageSize);
    SIZE_T size = end - start;

    // unprotect pages
    DWORD oldProtect;
    if (!VirtualProtect((LPVOID)start, size, PAGE_EXECUTE_READWRITE, &oldProtect))
        return FALSE;

    // restore bytes
    memcpy((void*)addr, original, len);
    FlushInstructionCache(GetCurrentProcess(), (LPCVOID)addr, len);

    // re-protect pages
    DWORD tmp;
    VirtualProtect((LPVOID)start, size, oldProtect, &tmp);

    return TRUE;
}

ULONG __fastcall SRTrampolineDispatcherBridge(
    void* rcx, void* rdx, void* r8, void* r9,
    void* r10, void* r11)
{
    SIERRA_HOOK_CTX ctx;
    void* retAddr = _ReturnAddress();

    for (int i = 0; i < SIERRA_MAX_HOOKS; ++i) {
        SIERRA_HOOK* hook = &gHookTable[i];
        if (!hook->TargetFunc) continue;
        if ((BYTE*)retAddr >= (BYTE*)hook->TargetFunc &&
            (BYTE*)retAddr < (BYTE*)hook->TargetFunc + hook->PatchLen)
        {
            ctx.HookedFunc = hook->TargetFunc;
            ctx.CleanProxy = hook->Trampoline;
            ctx.ModuleBase = hook->ModuleBase;
            return hook->Callback(&ctx);
        }
    }
    return SR_HOOK_NOT_FOUND;
}

ULONG SRDispatchInvoke(SIERRA_HOOK_CTX* ctx) {
    void* retAddr = _ReturnAddress();
    for (int i = 0; i < SIERRA_MAX_HOOKS; ++i) {
        SIERRA_HOOK* hook = &gHookTable[i];
        if (!hook->TargetFunc) continue;
        if ((BYTE*)retAddr >= (BYTE*)hook->TargetFunc &&
            (BYTE*)retAddr < (BYTE*)hook->TargetFunc + hook->PatchLen)
        {
            SIERRA_HOOK_CTX local = { 0 };
            local.HookedFunc = hook->TargetFunc;
            local.CleanProxy = hook->Trampoline;
            local.ModuleBase = hook->ModuleBase;
            return hook->Callback(&local);
        }
    }
    return SR_HOOK_NOT_FOUND;
}

BOOL SRSetHook(const wchar_t* moduleName, const char* funcName, SIERRA_CALLBACK callback, DWORD flags) {
    if (!moduleName || !funcName || !callback)
        return FALSE;

    void* mod = SRGetModuleBase(moduleName);
    if (!mod)
        return FALSE;

    DWORD hash = SRHash(funcName);
    void* target = SRGetProcedureAddrForCaller(mod, funcName, flags);
    if (!target)
        return FALSE;

    for (int i = 0; i < SIERRA_MAX_HOOKS; ++i) {
        void* expected = NULL;
        if (_InterlockedCompareExchangePointer(&gHookTable[i].TargetFunc, (void*)0x1, NULL) == NULL) {
            BYTE original[TRAMPOLINE_SIZE];
            SIZE_T len = 0;
            if (!SRIntercept(target, SRTrampolineDispatcherBridge, original, &len)) {
                gHookTable[i].TargetFunc = NULL;
                return FALSE;
            }

            gHookTable[i].Hash = hash;
            gHookTable[i].TargetFunc = target;
            memcpy(gHookTable[i].Original, original, len);
            gHookTable[i].PatchLen = len;
            gHookTable[i].Callback = callback;
            gHookTable[i].Flags = flags;
            gHookTable[i].ModuleBase = mod;

            return TRUE;
        }
    }

    return FALSE;
}