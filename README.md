![TITAN](https://avatars.githubusercontent.com/u/199383721?s=200&v=4)

# SIERRA API

**SIERRA** is a low-level C hooking, hook-evasion & IAT virtualization API

## OVERVIEW

Generally hooks are patched or destroyed, which creates instability and introduces detection vectors, instead Sierra proxies functions or performs a "step-over".

## WHY?

> *"Popular hooking API's/Fw's are easily signatured, Detours, Minhook, ...”*

Sierra is a smaller rewrite of the concepts seen in Detours/Minhook but with an emphasis on security & stealth in heavily guarded enviroments

* No disassembly libraries or VEH traps.
* No `VirtualProtect` loops.
* No static stubs.
* No IAT noise. No loader friction.
* No `.text` bloat
* Hard-to-sig

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

## License

**Creative Commons Attribution-NonCommercial 4.0 International (CC BY-NC 4.0)**  

[Full License](https://creativecommons.org/licenses/by-nc/4.0/)
