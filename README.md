![TITAN](https://avatars.githubusercontent.com/u/199383721?s=200&v=4)

# SIERRA Framework

**SIERRA** is a low-level C hooking, hook-evasion & IAT virtualization framework

Developed by **TITAN Softwork Solutions**

## Project Overview

Generally the hooks removed.
SIERRA doesn’t remove the hook — it sidesteps it, then hooks the proxy if you'd like.

No system unhooking. No static syscall stubs. No signatured detourture.
Just runtime trampoline redirection, memory-safe proxy slots, forwarder-aware resolution, and raw stack tracing — all done without disassemblers, wrappers, or dependency chains.

## Why?

> *"Popular hooking frameworks are extremely signatured, linking Detours gets flagged by every EDR in existance”*

That was the thought behind SIERRA.

Everyone uses Detours, MinHook, or some forked abstraction that bloats the IAT, sinks memory, touches loader internals, and leaves syscall-sized trails across memory. It works great — but it's loud.

SIERRA is a smaller rewrite of the idea, not the tooling.

* No reliance on CRT or WinAPI.
* No disassembly libraries or VEH traps.
* No `VirtualProtect` loops.
* No static stubs AVs can regex.
* No IAT noise. No loader friction.

Not because Detours or any of these projects are bad — they're brilliant.
But in low-noise, stealth-oriented environments, *overengineering is exposure*, and where security is crucial.

---

## API

The following symbols are exposed by `sierra.h`:

```c
// Function resolution (IAT Virtualization, IAT evasion)
void* SRGetModuleBase(const wchar_t* moduleName);
void* SRGetProcedureAddrForCaller(const void* base, const char* funcName, DWORD flags);

// Hook Installation
BOOL SRSetHook(const wchar_t* moduleName, const char* funcName, SIERRA_CALLBACK callback, DWORD flags);

// Hook Context
typedef struct _SIERRA_HOOK_CTX {
    void*       HookedFunc;
    void*       CleanProxy;
    const void* ModuleBase;
} SIERRA_HOOK_CTX;
```

---

## USAGE

See [`USAGE.md`](USAGE.md) for detailed examples.

---

## HEADERS

All code is exported through `sierra.h`.  
You must compile `sierra.c` into your project.

---

## LICENSE

This codebase is provided as-is under a modified MIT-style license.
Use is restricted to red team simulation, research, and offensive defense.

---

## ATTRIBUTION

Built by TITAN Softwork Solutions.
No external code used.
No upstream inspiration.

## License

**Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**  

[Full License](https://creativecommons.org/licenses/by-nc/4.0/)

## Disclaimer

This tool is for educational and research use only. Use at your own risk. You are solely responsible for how you use this code.
