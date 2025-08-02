#include "spec.h"

typedef void(WINAPI* FnRtlExitUserThread)(NTSTATUS);

int main() {
    printf("[[ SIERRA Testing Suite Initialized ]]\n\n");

    Run_HookTests();
    Run_ResolutionTests();
    Run_MemoryTests();
    Run_DelayTest();

    FnRtlExitUserThread exitThread = (FnRtlExitUserThread)SRGetProcedureAddrForCaller(
        SRGetModuleBase(L"ntdll.dll"), "RtlExitUserThread", SR_FLAG_ENABLE_SEH
    );

    printf("\n[[ SIERRA Testing Suite - All tests passed ]]\n");
    if (exitThread) exitThread(0x77777777);
    return 0;
}