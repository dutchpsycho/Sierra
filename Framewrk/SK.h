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


#define MAX_FRAMES 64
#define TRAMPOLINE_SIZE 32
#define SK_EXCEPTION_HOOK_DETECTED 0xE00000FF

#define SK_FLAG_NONE                0x0
#define SK_FLAG_ENABLE_SEH          0x1
#define SK_FLAG_DISABLE_TRAMPOLINE  0x2

#define SK_PROXY_PAGE_COUNT 4
#define SK_PROXY_PAGE_SIZE 4096
#define SK_PROXY_SLOT_SIZE 32
#define SK_PROXYS_PER_PAGE (SK_PROXY_PAGE_SIZE / SK_PROXY_SLOT_SIZE)
#define SK_TOTAL_SLOTS (SK_PROXY_PAGE_COUNT * SK_PROXYS_PER_PAGE)

typedef struct {
    DWORD Hash;
    void* OriginalFunc;
    void* TrampolineAddr;
    ULONGLONG LastUsedTick;
    volatile LONG InUse;
} SK_PROXY_SLOT;

typedef struct {
    void* Address;
    const char* Symbol;
} StackFrameHit;

typedef struct {
    void* HookedFunc;
    void* CleanProxy;
    const void* ModuleBase;
} SK_HOOK_CONTEXT;

extern void* gProxyPages[SK_PROXY_PAGE_COUNT];
extern SK_PROXY_SLOT gProxyTable[SK_TOTAL_SLOTS];
extern volatile LONG gProxySlotCounter;

void* SKGetModuleBase(const wchar_t* moduleName);
void* SKGetProcedureAddrForCaller(const void* base, const char* funcName, DWORD flags);

void SKProxyLRU(ULONGLONG olderThan);
void SKStackScan(StackFrameHit* hits, int* count);

#ifdef __cplusplus
}
#endif