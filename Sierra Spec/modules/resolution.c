#include "spec.h"

typedef NTSTATUS(NTAPI* FnNtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* FnLdrGetProcedureAddress)(void*, struct _ANSI_STRING*, ULONG, void**);

typedef struct _ANSI_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PSTR Buffer;
} ANSI_STRING;

typedef struct _PROCESS_BsASIC_INFORMATION {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

void RtlInitAnsiString(ANSI_STRING* dst, const char* src) {
    size_t len = strlen(src);
    dst->Length = (USHORT)len;
    dst->MaximumLength = (USHORT)(len + 1);
    dst->Buffer = (PSTR)src;
}

void Run_ResolutionTests() {
    void* ntdll = SRGetModuleBase(L"ntdll.dll");
    if (!ntdll) {
        printf("[!] failed to resolve ntdll\n");
        return;
    }

    FnNtQueryInformationProcess query = (FnNtQueryInformationProcess)SRGetProcedureAddrForCaller(
        ntdll, "NtQueryInformationProcess", SR_FLAG_ENABLE_SEH
    );

    PROCESS_BASIC_INFORMATION pbi = { 0 };
    ULONG retLen = 0;
    NTSTATUS s = query(GetCurrentProcess(), 0, &pbi, sizeof(pbi), &retLen);
    printf("[+] NtQueryInformationProcess => 0x%08X, PEB: 0x%p\n", s, pbi.PebBaseAddress);

    ANSI_STRING fn;
    void* out = NULL;
    RtlInitAnsiString(&fn, "NtClose");

    FnLdrGetProcedureAddress loader = (FnLdrGetProcedureAddress)SRGetProcedureAddrForCaller(
        ntdll, "LdrGetProcedureAddress", SR_FLAG_ENABLE_SEH
    );

    s = loader(ntdll, &fn, 0, &out);
    printf("[+] LdrGetProcedureAddress => 0x%08X, NtClose addr: 0x%p\n", s, out);
}
