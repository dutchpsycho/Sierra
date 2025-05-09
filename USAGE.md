# SIERRA USAGE

## HOOKING EXAMPLE

```c
#include "sierra.h"

ULONG MyHook(SIERRA_HOOK_CTX* ctx, ...) {
    // logic to execute when the hook triggers
    return 0x0;
}

int main() {
    SRSetHook(L"ntdll.dll", "NtQueryInformationProcess", MyHook, SR_FLAG_NONE);
}
````

---

## CALLBACK CONTEXT

```c
typedef struct _SIERRA_HOOK_CTX {
    void*       HookedFunc;
    void*       CleanProxy;
    const void* ModuleBase;
} SIERRA_HOOK_CTX;
```

* `HookedFunc` points to the original (possibly patched) target.
* `CleanProxy` is a trampoline pointing to the clean version.
* `ModuleBase` is the image base of the loaded module containing the function.

---

## MANUAL RESOLUTION

If you need to resolve and call APIs manually — without importing `GetProcAddress` or `LoadLibrary` — SIERRA exposes internal resolution routines:

```c
void* SRGetModuleBase(const wchar_t* moduleName);
void* SRGetProcedureAddrForCaller(const void* base, const char* funcName, DWORD flags);
```

### Example:

```c
void* ntdll = SRGetModuleBase(L"ntdll.dll");
void* func  = SRGetProcedureAddrForCaller(ntdll, "NtClose", SR_FLAG_NONE);
```

`SRGetProcedureAddrForCaller` will step over forwarders, avoid `.edata`, verify `.text` bounds, and optionally return a clean trampoline proxy if the original is hooked.

---

## FLAGS

| Macro                         | Behavior                                 |
| ----------------------------- | ---------------------------------------- |
| SR\_FLAG\_NONE                | Default behavior                         |
| SR\_FLAG\_ENABLE\_SEH         | Raises SEH exception if hook is detected |
| SR\_FLAG\_DISABLE\_TRAMPOLINE | Skips proxy generation entirely          |

---

## RESTORING PATCHES

To restore the original state of a hooked function:

```c
SRRestore(void* target, const BYTE* originalBytes, SIZE_T length);
```

Ensure `originalBytes` contains a valid copy of the original prologue. This is returned during `SRIntercept()` internally.

---

## PROXY SLOT CLEANUP

Trampoline memory pages are reused. For long-running processes, clean up stale slots periodically:

```c
SRProxyLRU(__rdtsc() - N);
```

Where `N` is the number of clock ticks since last use. This removes trampolines older than that threshold.
