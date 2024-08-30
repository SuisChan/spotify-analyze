#include "pch.h"

#include "pcap.h"
#include "shn.h"
#include "utils.h"

// 48 89 5C 24 08 48 89 6C 24 10 48 89 74 24 18 57 41 54 41 55 41 56 41 57 48 83
// EC 20 8B ?? CC 00 00 00
static const char *pattern =
    "\x48\x89\x5c\x24\x08\x48\x89\x6c\x24\x10\x48\x89\x74\x24\x18\x57\x41\x54"
    "\x41\x55\x41\x56\x41\x57\x48\x83\xec\x20\x8b\x00\xcc\x00\x00\x00";

static const char *mask = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxx?xxxx";

#define DIRECTION_SEND 0
#define DIRECTION_RECV 1

static HANDLE dump_fd;

typedef void(__cdecl *shn_decrypt_t)(shn_ctx *, UCHAR *, int);
shn_decrypt_t shn_decrypt_stub = nullptr;

typedef void(__cdecl *shn_encrypt_t)(shn_ctx *, UCHAR *, int);
shn_encrypt_t shn_encrypt_stub = nullptr;

int gettimeofday(struct timeval *tp, struct timezone *tzp) {
  // note: some broken versions only have 8 trailing zero's, the correct epoch
  // has 9 trailing zero's this magic number is the number of 100 nanosecond
  // intervals since january 1, 1601 (utc) until 00:00:00 january 1, 1970
  static const uint64_t epoch = ((uint64_t)116444736000000000ull);

  SYSTEMTIME system_time;
  FILETIME file_time;
  uint64_t time;

  GetSystemTime(&system_time);
  SystemTimeToFileTime(&system_time, &file_time);
  time = ((uint64_t)file_time.dwLowDateTime);
  time += ((uint64_t)file_time.dwHighDateTime) << 32;

  tp->tv_sec = (long)((time - epoch) / 10000000l);
  tp->tv_usec = (long)(system_time.wMilliseconds * 1000);
  return 0;
}

void __cdecl shn_decrypt_proxy(shn_ctx *c, UCHAR *buf, int nBytes) {
  shn_decrypt(c, buf, nBytes);

#pragma pack(push, 1)
  static struct {
    uint8_t cmd;
    uint16_t length;
  } header = {0, 0};
#pragma pack(pop)

  if (header.cmd == 0) {
    if (nBytes == 3)
      memcpy(&header, buf, 3);
  } else {
    if (nBytes == ntohs(header.length)) {
      struct timeval tv;
      gettimeofday(&tv, NULL);
      pcap_write_packet_header(dump_fd, &tv, 4 + nBytes);

      uint8_t direction = DIRECTION_RECV;
      WriteFile(dump_fd, &direction, 1, NULL, NULL);
      WriteFile(dump_fd, &header, 3, NULL, NULL);
      WriteFile(dump_fd, buf, nBytes, NULL, NULL);
    }

    header.cmd = 0;
  }
}

void __cdecl shn_encrypt_proxy(shn_ctx *c, UCHAR *buf, int nBytes) {
  struct timeval tv;
  gettimeofday(&tv, NULL);
  pcap_write_packet_header(dump_fd, &tv, 1 + nBytes);

  uint8_t direction = DIRECTION_SEND;
  WriteFile(dump_fd, &direction, 1, NULL, NULL);
  WriteFile(dump_fd, buf, nBytes, NULL, NULL);

  shn_encrypt(c, buf, nBytes);
}

DWORD WINAPI ThreadProc(_In_ LPVOID lpParameter) {
  MODULEINFO mInfo = utils::GetModuleInfo(NULL);

  auto shn_decrypt = utils::FindPattern(
      pattern, mask, (char *)mInfo.lpBaseOfDll, mInfo.SizeOfImage);

  if (shn_decrypt == nullptr) {
    MessageBoxA(NULL, "shn_decrypt is nullptr", "error", MB_ICONERROR);
    return 1;
  }

  char *newPos = (char *)(shn_decrypt + strlen(mask));

  uintptr_t newSize = mInfo.SizeOfImage -
                      ((uintptr_t)shn_decrypt - (uintptr_t)mInfo.lpBaseOfDll) -
                      strlen(mask);

  auto shn_encrypt = utils::FindPattern(pattern, mask, newPos, newSize);

  if (shn_decrypt == nullptr) {
    MessageBoxA(NULL, "shn_encrypt is nullptr", "error", MB_ICONERROR);
    return 1;
  }

  dump_fd = CreateFileA("dump.pcap", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                        FILE_ATTRIBUTE_NORMAL, NULL);

  pcap_write_header(dump_fd, PCAP_DLT_USER0);

  shn_encrypt_stub = (shn_encrypt_t)utils::InstallHook(
      (void *)shn_encrypt, (void *)shn_encrypt_proxy);

  shn_decrypt_stub = (shn_decrypt_t)utils::InstallHook(
      (void *)shn_decrypt, (void *)shn_decrypt_proxy);

  return 0;
};

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call,
                      LPVOID lpReserved) {

  if (ul_reason_for_call == DLL_PROCESS_ATTACH) {
    CreateThread(NULL, 0, &ThreadProc, NULL, 0, NULL);
  }

  return TRUE;
}
