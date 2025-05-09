#include "test.h"

typedef NTSTATUS(NTAPI* FnNtReadVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);
typedef NTSTATUS(NTAPI* FnNtWriteVirtualMemory)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

void Run_MemoryTests() {
    FnNtReadVirtualMemory read = (FnNtReadVirtualMemory)SRGetProcedureAddrForCaller(
        SRGetModuleBase(L"ntdll.dll"), "NtReadVirtualMemory", SR_FLAG_ENABLE_SEH
    );

    FnNtWriteVirtualMemory write = (FnNtWriteVirtualMemory)SRGetProcedureAddrForCaller(
        SRGetModuleBase(L"ntdll.dll"), "NtWriteVirtualMemory", SR_FLAG_ENABLE_SEH
    );

    uint8_t buffer[16] = {};
    SIZE_T readBytes = 0;
    NTSTATUS s = read(GetCurrentProcess(), &s, buffer, sizeof(buffer), &readBytes);
    printf("[+] NtReadVirtualMemory => 0x%08X (%llu bytes)\n", s, readBytes);

    uint32_t newVal = 0xDEADBEEF, outVal = 0;
    SIZE_T written = 0;
    s = write(GetCurrentProcess(), &outVal, &newVal, sizeof(newVal), &written);
    printf("[+] NtWriteVirtualMemory => 0x%08X (%llu bytes), new val: 0x%X\n", s, written, outVal);
}
