#pragma once
#include "../Framework/sierra.h"

#include <windows.h>
#include <stdint.h>
#include <stdio.h>

typedef LONG NTSTATUS;

void Run_HookTests(void);
void Run_ResolutionTests(void);
void Run_MemoryTests(void);
void Run_DelayTest(void);