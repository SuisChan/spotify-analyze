#pragma once
#include "pch.h"

class utils {
public:
  static void *AllocatePageNearAddress(void *targetAddr);
  static void WriteAbsoluteJump64(void *absJumpMemory, void *addrToJumpTo);
  static void *InstallHook(void *func2hook, void *payloadFunction);

  static MODULEINFO GetModuleInfo(char *szModule);
  static const char *FindPattern(const char *pattern, const char *mask,
                                 const char *begin, size_t size);
};
