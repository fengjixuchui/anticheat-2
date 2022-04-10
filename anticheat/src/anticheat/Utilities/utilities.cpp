#include "utilities.hpp"

std::map<LPVOID, DWORD> __cdecl BuildModuledMemoryMap() // NtKernelMC/MDE on github
{
	std::map<LPVOID, DWORD> memoryMap; 

	HMODULE psapiMod = GetModuleHandleA("psapi.dll");
	if (!psapiMod)
		return memoryMap;

	PtrEnumProcessModules EnumProcModules = (PtrEnumProcessModules)GetProcAddress(psapiMod, "EnumProcessModules");
	GetMdlInfoP GetMdlInfo = (GetMdlInfoP)GetProcAddress(psapiMod, "GetModuleInformation");

	DWORD lpcbNeeded;
	HMODULE hModules[1024];
	EnumProcModules(GetCurrentProcess(), hModules, sizeof(hModules), &lpcbNeeded);
	for (unsigned int i = 0; i < (lpcbNeeded / sizeof(HMODULE)); i++)
	{
		MODULEINFO modinfo; 
		GetMdlInfo(GetCurrentProcess(), hModules[i], &modinfo, sizeof(modinfo));
		memoryMap.insert(memoryMap.begin(), std::pair<LPVOID, DWORD>(modinfo.lpBaseOfDll, modinfo.SizeOfImage));
	}
	return memoryMap;
}

bool __cdecl IsMemoryInModuledRange(LPVOID base)
{
	std::map<LPVOID, DWORD> memory = BuildModuledMemoryMap();
	for (const auto& it : memory)
	{
		if (base >= it.first && base <= (LPVOID)((uint64_t)it.first + it.second)) return true;
	}
	return false;
}