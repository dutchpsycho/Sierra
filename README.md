![TITAN](https://avatars.githubusercontent.com/u/199383721?s=200&v=4)

# SK Framework

**SK** is an open-source fast lightweight function proxying framework designed to bypass usermode API hooks by scanning, validating, and replicating clean prologues of exported functions into dynamic trampoline slots. Developed by **TITAN Softwork Solutions**.

Unlike [ActiveBreach](https://github.com/dutchpsycho/ActiveBreach-Engine), SK does not perform syscalls directly. Instead, it focuses on ensuring clean and safe API usage inside hostile, hooked environments.

It’s your first line of defense when executing APIs without tipping off userland monitoring tools.

---

## Features

- Extremely fast
- IAT virtualization: resolved APIs do not populate the import table (no `.idata` footprint)
- Hook-Sidestepping: if a hook is detected, the function is trampoline-wrapped and cleaned, we don't touch the actual hook
- Trampoline re-use, no memory clog, LRU system implemented
- Stack-safe, trampoline-based execution
- No reliance on `GetProcAddress` or import tables
- Optional SEH flags for detecting hooks

---

## Integration

SK is a drop-in framework. Add `SK.c` and `SK.h` to your tooling stack or loader runtime. It allocates executable trampolines in memory and safely copies only valid, clean prologues from API functions.

- x64 Windows (10/11)
- C (compiled with MSVC / Visual Studio)
- No dependencies

---

## Usage Example

This is a quick usage guide to integrate SK into your redteam project or loader.

### Example: Resolving NtCreateThreadEx

```c
#include "SK.h"

typedef NTSTATUS (NTAPI *NtCreateThreadEx_t)(HANDLE*, ACCESS_MASK, POBJECT_ATTRIBUTES, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

int main() {
    void* ntdll = SKGetModuleBase(L"ntdll.dll");
    if (!ntdll) return -1;

    void* proxy = SKGetProcedureAddrForCaller(ntdll, "NtCreateThreadEx", SK_FLAG_NONE);
    if (!proxy) return -1;

    NtCreateThreadEx_t NtCreateThreadEx = (NtCreateThreadEx_t)proxy;

    // use NtCreateThreadEx(...) safely
    return 0;
}
```

---

### Example: Resolving a Non-Exported Internal Stub (e.g. KiUserApcDispatcher)

```c
#include "SK.h"

#define KIUSERAPC_RVA 0x1234 // This is an EXAMPLE

int main() {
    void* ntdll = SKGetModuleBase(L"ntdll.dll");
    if (!ntdll) return -1;

    void* target = (BYTE*)ntdll + KIUSERAPC_RVA;

    void* trampoline = SKProxyResolveHashed(SKHash("KiUserApcDispatcher"), target);
    if (!trampoline) return -1;

    // cast and call trampoline if needed
    return 0;
}
```

This method works for internal stubs that are not part of the export table, as long as the RVA is known and verified/resolved.

---

## Clean Proxy Behavior

- Trampolines are allocated in executable memory
- Original function prologue is copied safely (excluding hooks)
- `SKIsLikelyHook` checks for jmp, call, push-ret shims
- Function copying terminates on clean `ret` or known syscall stub

---

## Notes

- This is not a traditional DLL/lib you link to your project, you add `SK.c` to your project's codebase & compile it in
- `SK_FLAG_ENABLE_SEH` can be set to trigger a debug exception on hook detection
- `SKProxyLRU` should be called periodically to clean old trampolines
- Export names are hashed using `SKHash` — no raw strings are used in memory

---

## Disclaimer

This tool is for educational and research use only. Use at your own risk. You are solely responsible for how you use this code.

