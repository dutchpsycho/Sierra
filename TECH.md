# TECHNICAL OVERVIEW — SIERRA

## CORE MECHANICS

### Hashing (`SRHash`)

SIERRA resolves export symbols using a case-insensitive hash algorithm:

* FNV-style base
* Rotating XOR key
* Tail-mixed with avalanche bit-twisting

used internally for all symbol lookups — ensures no raw strings or API names appear in memory post-compile.

---

### Symbol Resolution (`SRGetProcedureAddrForCaller`, `SRGetModuleBase`)

these two are the foundation of the framework.
before trampolines, before patching — sierra isolates and redirects at the symbol layer.

* **`SRGetModuleBase`** walks the PEB LDR list, manually resolving loaded modules w/o touching imports or the loader.
* **`SRGetProcedureAddrForCaller`** performs a manual export walk, detects `.edata` forwarded entries, recursively resolves reexports, and rejects non-text pointers or hooks.

if everything checks out, it proxies the function via `SRProxyResolveHashed` — bypassing both IAT resolution and trampoline detection.

---

### Proxy Slots (`SRProxyResolveHashed`)

trampolines are stored in fixed-size slot pages:

* each page holds 128–256 trampolines
* `__rdtsc`-based timestamping for LRU
* reuse-safe — each slot gets wiped + reassigned

acts as the execution bridge to clean, reconstructed function stubs.

---

### Stack Frame Scanner (`SRStackScan`)

walks the raw frame pointer chain from `_AddressOfReturnAddress()` — no reliance on `RtlCaptureStackBackTrace`, no dependency on SEH or frame pointers being intact.

extremely useful for context recovery and tracing injected call chains.

---

### Hook Detection (`SRIsLikelyHook`)

uses static byte-pattern checks to detect common detour stubs:

* `jmp rel32`, `jmp [mem]`
* `push addr ; ret`
* `movabs rax ; call/jmp rax`

detected stubs are neutered into a single `ret` in the proxy slot.

---

### Trampoline Generation (`SRpEngine`)

randomized patch stubs are built from four templates:

* `push rax ; mov rax ; xchg [rsp], rax ; ret`
* `mov rax ; push rax ; ret`
* `push imm64 (imm32 + mov high) ; ret`
* `pushfq ; mov ; xchg ; popfq ; ret`

these avoid consistent signatures and maintain RIP alignment + return fidelity.

---

### Hook Dispatcher (`SRTrampolineDispatcherBridge`)

once a trampoline is hit:

1. return address is scanned
2. matched against registered hooks
3. callback is invoked with `SIERRA_HOOK_CTX`:

   * `HookedFunc`, `CleanProxy`, `ModuleBase`

all internal — no userland debugging APIs or stack introspection.

---

### Cleanup (`SRProxyLRU`)

trampolines are wiped if unused for longer than a `__rdtsc` threshold.

this reduces exposure in long-lived processes or implants by constantly purging cold slots.

---

## RUNTIME SAFETY

* all memory operations guarded by `__try / __except`
* failed patching falls back to safe `ret`
* stack scanning aborts cleanly on invalid memory
* no use of SEH, VEH, TLS, or loader interaction

---

## DESIGN GOALS

| Principle      | Description                                                         |
| -------------- | ------------------------------------------------------------------- |
| Inline-Only    | no VEH, no kernel interaction, no hijacked threads                  |
| No Disassembly | instruction boundary detection uses shape-based logic, not decoding |
| Reloc-Aware    | trampolines adjust RIP-relative offsets manually                    |
| Fast Pathing   | slot cache uses interlocked LRU over static memory                  |
| Self-Contained | zero CRT, zero dynamic allocs, minimal WinAPI usage                 |
| Loader-Free    | symbols resolved manually, loader state is bypassed                 |
