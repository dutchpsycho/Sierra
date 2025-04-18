# SK Framework Usage

This is a quick usage guide to integrate SK into your redteam project or loader.

---

## 🎯 Goal

Use SK to safely resolve and call Windows API functions **without triggering EDR hooks**.

---

## 🔧 Example: Resolving NtCreateThreadEx

```cpp
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

## 🔐 Clean Proxy Behavior

- Trampolines are allocated in executable memory
- Original function prologue is copied safely (excluding hooks)
- `SKIsLikelyHook` checks for jmp, call, push-ret shims
- Function copying terminates on clean `ret` or known syscall stub

---

## 🛑 Notes

- `SK_FLAG_ENABLE_SEH` can be set to trigger a debug exception on hook detection
- `SKProxyLRU` should be called periodically to clean old trampolines
- Export names are hashed using SKHash — no raw strings are used in memory

---

## 🧠 Gotchas

- This framework doesn’t perform the syscall — it resolves the function cleanly.
- Best paired with a syscall invoker like ActiveBreach.


