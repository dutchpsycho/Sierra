/*
 * ==================================================================================
 *  Repository:   Sierra Framework
 *  Project:      Sierra
 *  File:         sierra.h
 *  Author:       DutchPsycho
 *  Organization: TITAN Softwork Solutions
 *
 *  Description:
 *      SIERRA is a runtime control-flow redirection framework for x64 usermode.
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

#pragma once

#include <windows.h>
#include <winnt.h>
#include <intrin.h>
#include <stddef.h>
#include <string.h>

#pragma intrinsic(__readgsqword)

#ifdef __cplusplus
extern "C" {
#endif

#ifndef _UNICODE_STRING_DEFINED
#define _UNICODE_STRING_DEFINED
    typedef struct _UNICODE_STRING {
        USHORT Length;
        USHORT MaximumLength;
        PWSTR  Buffer;
    } UNICODE_STRING;
#endif

#ifndef _LDR_DATA_TABLE_ENTRY_DEFINED
#define _LDR_DATA_TABLE_ENTRY_DEFINED
    typedef struct _LDR_DATA_TABLE_ENTRY {
        LIST_ENTRY InLoadOrderLinks;
        LIST_ENTRY InMemoryOrderLinks;
        LIST_ENTRY InInitializationOrderLinks;
        void* DllBase;
        void* EntryPoint;
        ULONG SizeOfImage;
        UNICODE_STRING FullDllName;
        UNICODE_STRING BaseDllName;
    } LDR_DATA_TABLE_ENTRY;
#endif

#ifndef _PEB_LDR_DATA_DEFINED
#define _PEB_LDR_DATA_DEFINED
    typedef struct _PEB_LDR_DATA {
        ULONG Length;
        BOOLEAN Initialized;
        void* SsHandle;
        LIST_ENTRY InLoadOrderModuleList;
        LIST_ENTRY InMemoryOrderModuleList;
        LIST_ENTRY InInitializationOrderModuleList;
    } PEB_LDR_DATA;
#endif

#ifndef _PEB_DEFINED
#define _PEB_DEFINED
    typedef struct _PEB {
        BYTE Reserved1[2];
        BYTE BeingDebugged;
        BYTE Reserved2[1];
        void* Reserved3[2];
        PEB_LDR_DATA* Ldr;
    } PEB;
#endif

#define MAX_FRAMES                 64
#define TRAMPOLINE_SIZE            32
#define SR_EXCEPTION_HOOK_DETECTED 0xE00000FF

#define SR_FLAG_NONE               0x0
#define SR_FLAG_ENABLE_SEH         0x1
#define SR_FLAG_DISABLE_TRAMPOLINE 0x2
#define SR_HOOK_NOT_FOUND          0x8

#define SR_PROXY_PAGE_COUNT 4
#define SR_PROXY_PAGE_SIZE  4096
#define SR_PROXY_SLOT_SIZE  32
#define SR_PROXYS_PER_PAGE  (SR_PROXY_PAGE_SIZE / SR_PROXY_SLOT_SIZE)
#define SR_TOTAL_SLOTS      (SR_PROXY_PAGE_COUNT * SR_PROXYS_PER_PAGE)

typedef struct _SIERRA_HOOK_CTX {
    void*       HookedFunc;
    void*       CleanProxy;
    const void* ModuleBase;
} SIERRA_HOOK_CTX;

typedef ULONG(*SIERRA_CALLBACK)(SIERRA_HOOK_CTX* ctx, ...);

typedef struct _SIERRA_HOOK {
    DWORD       Hash;
    void* TargetFunc;
    void* Trampoline;
    BYTE        Original[TRAMPOLINE_SIZE];
    SIZE_T      PatchLen;
    SIERRA_CALLBACK Callback;
    DWORD       Flags;
    void* ModuleBase;
} SIERRA_HOOK;

#define SIERRA_MAX_HOOKS 128
extern SIERRA_HOOK gHookTable[SIERRA_MAX_HOOKS];

typedef struct {
    DWORD       Hash;
    void*       OriginalFunc;
    void*       TrampolineAddr;
    ULONGLONG   LastUsedTick;
    volatile LONG InUse;
} SR_PROXY_SLOT;

typedef struct {
    void*        Address;
    const char*  Symbol;
} StackFrameHit;

extern void*       gProxyPages[SR_PROXY_PAGE_COUNT];
extern SR_PROXY_SLOT gProxyTable[SR_TOTAL_SLOTS];
extern volatile LONG gProxySlotCounter;

void*   SRGetModuleBase(const wchar_t* moduleName);
void*   SRGetProcedureAddrForCaller(const void* base, const char* funcName, DWORD flags);
void    SRProxyLRU(ULONGLONG olderThan);
void    SRStackScan(StackFrameHit* hits, int* count);

BOOL SRSetHook(const wchar_t* moduleName, const char* funcName, SIERRA_CALLBACK callback, DWORD flags);

ULONG   SRDispatchInvoke(SIERRA_HOOK_CTX* ctx);
ULONG   __fastcall SRTrampolineDispatcherBridge(void* rcx, void* rdx, void* r8, void* r9, void* r10, void* r11);

UINT_PTR PageAlignDown(UINT_PTR addr, SIZE_T pageSize);
UINT_PTR PageAlignUp(UINT_PTR addr, SIZE_T len, SIZE_T pageSize);

#ifdef __cplusplus
}
#endif