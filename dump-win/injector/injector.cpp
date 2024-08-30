#include <iostream>

#include <Windows.h>

#include <TlHelp32.h>

static const char *DLL_FILE = "core.dll";
static const wchar_t *TARGET = L"Spotify.exe";

DWORD GetProcId(const wchar_t *procName) {
  DWORD procId = 0;
  HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);

  if (hSnap != INVALID_HANDLE_VALUE) {
    PROCESSENTRY32 procEntry;
    procEntry.dwSize = sizeof(procEntry);

    if (Process32First(hSnap, &procEntry)) {
      do {
        if (!wcscmp(procEntry.szExeFile, procName)) {
          procId = procEntry.th32ProcessID;
          break;
        }
      } while (Process32Next(hSnap, &procEntry));
    }
  }

  CloseHandle(hSnap);
  return procId;
}

int main() {
  std::wcout << "Attempting to inject \"" << DLL_FILE << "\" into \""
             << std::wstring(TARGET) << "\"..." << std::endl;

  DWORD procId = 0;
  while (!procId) {
    procId = GetProcId(TARGET);
    Sleep(50);
  }

  // Possibly injecting too fast into Spotify.exe resulting in an error, so
  // delay?
  Sleep(50);

  HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, 0, procId);

  if (hProcess && hProcess != INVALID_HANDLE_VALUE) {
    void *loc = VirtualAllocEx(hProcess, 0, MAX_PATH, MEM_COMMIT | MEM_RESERVE,
                               PAGE_READWRITE);

    WriteProcessMemory(hProcess, loc, DLL_FILE, strlen(DLL_FILE) + 1, 0);

    HANDLE hThread = CreateRemoteThread(
        hProcess, 0, 0, (LPTHREAD_START_ROUTINE)LoadLibraryA, loc, 0, 0);

    if (hThread) {
      CloseHandle(hThread);
    }
  }

  if (hProcess) {
    CloseHandle(hProcess);
  }

  std::cout << "Done" << std::endl;
}
