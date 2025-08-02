#include "spec.h"

typedef NTSTATUS(NTAPI* FnNtDelayExecution)(BOOLEAN, PLARGE_INTEGER);

void Run_DelayTest() {
    FnNtDelayExecution delay = (FnNtDelayExecution)SRGetProcedureAddrForCaller(
        SRGetModuleBase(L"ntdll.dll"), "NtDelayExecution", SR_FLAG_ENABLE_SEH
    );

    LARGE_INTEGER t;
    t.QuadPart = -(10 * 1000 * 1000); // 1s
    NTSTATUS s = delay(FALSE, &t);
    printf("[+] NtDelayExecution(1s) => 0x%08X\n", s);
}