#include "SK.h"

#include <windows.h>
#include <stdio.h>
#include <stdint.h>

typedef LONG NTSTATUS;
typedef struct _PROCESS_BASIC_INFORMATION {
    PVOID Reserved1;
    PVOID PebBaseAddress;
    PVOID Reserved2[2];
    ULONG_PTR UniqueProcessId;
    PVOID Reserved3;
} PROCESS_BASIC_INFORMATION;

typedef struct _ANSI_STRING {
    USHORT Length;
    USHORT MaximumLength;
    PSTR Buffer;
} ANSI_STRING;

typedef NTSTATUS(NTAPI* FnNtQueryInformationProcess)(HANDLE, ULONG, PVOID, ULONG, PULONG);
typedef NTSTATUS(NTAPI* FnLdrGetProcedureAddress)(void*, ANSI_STRING*, ULONG, void**);
typedef void (WINAPI* FnRtlExitUserThread)(NTSTATUS);
typedef NTSTATUS(NTAPI* FnNtDelayExecution)(BOOLEAN, PLARGE_INTEGER);
typedef NTSTATUS(NTAPI* FnNtClose)(HANDLE);
typedef NTSTATUS(NTAPI* FnNtReadVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI* FnNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

void RtlInitAnsiString(ANSI_STRING* dst, const char* src) {
    if (!src) {
        dst->Length = 0;
        dst->MaximumLength = 0;
        dst->Buffer = NULL;
        return;
    }

    size_t len = strlen(src);
    dst->Length = (USHORT)len;
    dst->MaximumLength = (USHORT)(len + 1);
    dst->Buffer = (PSTR)src;
}

int main() {
    printf("[*] sk functional api tester running\n");

    void* ntdll = SKGetModuleBase(L"ntdll.dll");
    if (!ntdll) {
        printf("[!] failed to resolve ntdll\n");
        return 1;
    }

    FnNtQueryInformationProcess pNtQueryInformationProcess = (FnNtQueryInformationProcess)SKGetProcedureAddrForCaller(ntdll, "NtQueryInformationProcess", SK_FLAG_ENABLE_SEH);
    FnLdrGetProcedureAddress pLdrGetProcedureAddress = (FnLdrGetProcedureAddress)SKGetProcedureAddrForCaller(ntdll, "LdrGetProcedureAddress", SK_FLAG_ENABLE_SEH);
    FnRtlExitUserThread pRtlExitUserThread = (FnRtlExitUserThread)SKGetProcedureAddrForCaller(ntdll, "RtlExitUserThread", SK_FLAG_ENABLE_SEH);
    FnNtDelayExecution pNtDelayExecution = (FnNtDelayExecution)SKGetProcedureAddrForCaller(ntdll, "NtDelayExecution", SK_FLAG_ENABLE_SEH);
    FnNtClose pNtClose = (FnNtClose)SKGetProcedureAddrForCaller(ntdll, "NtClose", SK_FLAG_ENABLE_SEH);
    FnNtReadVirtualMemory pNtReadVirtualMemory = (FnNtReadVirtualMemory)SKGetProcedureAddrForCaller(ntdll, "NtReadVirtualMemory", SK_FLAG_ENABLE_SEH);
    FnNtWriteVirtualMemory pNtWriteVirtualMemory = (FnNtWriteVirtualMemory)SKGetProcedureAddrForCaller(ntdll, "NtWriteVirtualMemory", SK_FLAG_ENABLE_SEH);

    if (!pNtQueryInformationProcess || !pLdrGetProcedureAddress || !pRtlExitUserThread || !pNtDelayExecution ||
        !pNtClose || !pNtReadVirtualMemory || !pNtWriteVirtualMemory) {
        printf("[!] failed to resolve one or more target functions\n");
        return 1;
    }

    printf("[+] all apis resolved, testing now...\n");

    PROCESS_BASIC_INFORMATION pbi = { 0 };
    ULONG retLen = 0;
    NTSTATUS status = pNtQueryInformationProcess(GetCurrentProcess(), 0, &pbi, sizeof(pbi), &retLen);
    printf("[+] NtQueryInformationProcess => 0x%08X, PEB: 0x%p\n", status, pbi.PebBaseAddress);

    ANSI_STRING funcName;
    RtlInitAnsiString(&funcName, "NtClose");
    void* ntCloseAddr = NULL;
    status = pLdrGetProcedureAddress(ntdll, &funcName, 0, &ntCloseAddr);
    printf("[+] LdrGetProcedureAddress(NtClose) => 0x%08X, addr: 0x%p\n", status, ntCloseAddr);

    LARGE_INTEGER delay;
    delay.QuadPart = -(10 * 1000 * 1000);
    status = pNtDelayExecution(FALSE, &delay);
    printf("[+] NtDelayExecution(1s) => 0x%08X\n", status);

    SIZE_T bytesRead = 0;
    uint8_t buffer[16] = {};
    status = pNtReadVirtualMemory(GetCurrentProcess(), &status, buffer, sizeof(buffer), &bytesRead);
    printf("[+] NtReadVirtualMemory => 0x%08X (%llu bytes)\n", status, bytesRead);

    SIZE_T bytesWritten = 0;
    uint32_t fakeVal = 0xDEADBEEF;
    uint32_t targetVal = 0;
    status = pNtWriteVirtualMemory(GetCurrentProcess(), &targetVal, &fakeVal, sizeof(fakeVal), &bytesWritten);
    printf("[+] NtWriteVirtualMemory => 0x%08X (%llu bytes), new val: 0x%X\n", status, bytesWritten, targetVal);

    HANDLE self = GetCurrentProcess();
    HANDLE duped = NULL;
    DuplicateHandle(self, self, self, &duped, 0, FALSE, DUPLICATE_SAME_ACCESS);
    status = pNtClose(duped);
    printf("[+] NtClose(duped handle) => 0x%08X\n", status);

    printf("\n[~] all apis tested. exiting now.\n");
    pRtlExitUserThread(0x77777777);
    return 0;
}
