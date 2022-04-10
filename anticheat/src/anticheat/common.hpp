#include <windows.h>
#include <thread>
#include <vector>
#include <functional>
#include <TlHelp32.h>
#include <map>
#include <Psapi.h>
#include <winternl.h>
#include <winnt.h>
#include <intrin.h>
#include "../../vendors/MinHook/MinHook.h"

#ifndef _DEBUG
#define ANTICHEAT_INLINE __forceinline
#else
#define ANTICHEAT_INLINE inline
#endif

#define AC_SUCCESS(x) (x > 0)

#ifndef COMMONS_H
#define COMMONS_H


typedef LONG ACSTATUS;
typedef BOOL(__stdcall* PtrEnumProcessModules)(HANDLE hProcess, HMODULE* lphModule, DWORD cb, LPDWORD lpcbNeeded);
typedef BOOL(__stdcall* GetMdlInfoP)(HANDLE hProcess, HMODULE hModule, LPMODULEINFO lpmodinfo, DWORD cb);
typedef NTSTATUS(__stdcall* tNtQueryInformationThread)(HANDLE ThreadHandle, THREADINFOCLASS ThreadInformationClass, PVOID ThreadInformation, ULONG ThreadInformationLength, PULONG ReturnLength);

typedef enum _MEMORY_INFORMATION_CLASS {
	MemoryBasicInformation
} MEMORY_INFORMATION_CLASS;

typedef LONG(WINAPI* ZWQUERYVIRTUALMEMORY)(
	HANDLE ProcessHandle,
	PVOID BaseAddress,
	MEMORY_INFORMATION_CLASS MemoryInformationClass,
	PVOID MemoryInformation,
	ULONG MemoryInformationLength,
	PULONG ReturnLength
);

#endif // COMMONS_H