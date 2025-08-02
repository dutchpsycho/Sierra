#include "spec.h"

typedef NTSTATUS(NTAPI* FnNtClose)(HANDLE);

ULONG MyNtCloseHook(SIERRA_HOOK_CTX* ctx, HANDLE h) {
    printf("[!] NtClose hook triggered! handle: 0x%p\n", h);
    FnNtClose orig = (FnNtClose)ctx->CleanProxy;
    return orig ? orig(h) : 0;
}

void Run_HookTests() {
    if (!SRSetHook(L"ntdll.dll", "NtClose", MyNtCloseHook, SR_FLAG_NONE)) {
        printf("[!] failed to hook NtClose\n");
        return;
    }

    HANDLE self = GetCurrentProcess(), duped = NULL;
    DuplicateHandle(self, self, self, &duped, 0, FALSE, DUPLICATE_SAME_ACCESS);
    FnNtClose close = (FnNtClose)SRGetProcedureAddrForCaller(
        SRGetModuleBase(L"ntdll.dll"), "NtClose", SR_FLAG_ENABLE_SEH
    );
    if (close) {
        NTSTATUS s = close(duped);
        printf("[+] NtClose (duped) => 0x%08X\n", s);
    }
}