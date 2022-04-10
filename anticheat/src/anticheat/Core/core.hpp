#include "../common.hpp"
#include "../Utilities/utilities.hpp"

namespace hooks
{
	void* original_ldrloaddll = nullptr;

	LONG WINAPI LdrLoadDll_HOOK(PWSTR SearchPath OPTIONAL, PULONG DllCharacteristics OPTIONAL, PUNICODE_STRING DllName, PVOID* BaseAddress);
}

LONG WINAPI exceptions_handler(_EXCEPTION_POINTERS* ExceptionInfo);

class anticheat
{
public:

	struct Config
	{
		bool debug;
		bool threads_protection;
		bool suspicious_threads;
		bool ldrloaddll_cb;
		bool illegal_exception;
	};

	struct DetectionCb 
	{
		std::function<void()> threadProtection;
		std::function<void()> suspiciousThread;
		std::function<bool(PWSTR path)> ldrloadllCb;
		std::function<void()> outsideModException;
	};

	DetectionCb m_DetectionCallbacks;

private:

	Config m_Config;
	std::function<void()> m_onceInit;
	std::vector<std::pair<bool, std::function<void()>>> m_ProtectedThreads;
	std::vector<DWORD> m_ProtectedThreadsIds;

private: // detections
	
	ANTICHEAT_INLINE void ThreadsProtection()
	{
		auto EnumThreadsIds = []() {
			std::vector<DWORD> ret;

			HANDLE hSnapThread;
			PTHREADENTRY32 pte32 = new THREADENTRY32;
			pte32->dwSize = sizeof(THREADENTRY32);
			hSnapThread = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

			if (Thread32Next(hSnapThread, pte32))
			{
				do
				{
					if (GetCurrentProcessId() == pte32->th32OwnerProcessID)
					{
						ret.push_back(pte32->th32ThreadID);
					}
				} while (Thread32Next(hSnapThread, pte32));
			}

			CloseHandle(hSnapThread);
			delete pte32;

			return ret;
		};

		while (true) 
		{
			Sleep(2500);
			for (const auto& ourThreads : this->m_ProtectedThreadsIds)
			{
				auto cur_threads = EnumThreadsIds();

				if(!std::count(cur_threads.begin(), cur_threads.end(), ourThreads))
					this->m_DetectionCallbacks.threadProtection();
			}
		}
	}

	ANTICHEAT_INLINE void SuspiciousThreads()
	{
		auto EnumThreadsAddy = []() {
			std::vector<uintptr_t> ret;

			HANDLE hSnapThread;
			PTHREADENTRY32 pte32 = new THREADENTRY32;
			pte32->dwSize = sizeof(THREADENTRY32);
			hSnapThread = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

			tNtQueryInformationThread NtQueryInformationThread = (tNtQueryInformationThread)GetProcAddress(GetModuleHandleA("ntdll.dll"), "NtQueryInformationThread");

			if (Thread32Next(hSnapThread, pte32))
			{
				do
				{
					if (GetCurrentProcessId() == pte32->th32OwnerProcessID)
					{
						HANDLE target = OpenThread(THREAD_ALL_ACCESS, FALSE, pte32->th32ThreadID);
						if (target) {
							uintptr_t base = NULL;
							NtQueryInformationThread(target, (THREADINFOCLASS)9, &base, sizeof(uint64_t), NULL);
							ret.push_back(base);
						}
						CloseHandle(target);
					}
				} while (Thread32Next(hSnapThread, pte32));
			}

			CloseHandle(hSnapThread);
			delete pte32;

			return ret;
		};

		while (true)
		{
			for (const auto& thBase : EnumThreadsAddy())
			{
				if (!IsMemoryInModuledRange((LPVOID)thBase))
				{
					this->m_DetectionCallbacks.suspiciousThread();
				}
			}

			Sleep(1);
		}
	}
public:

	anticheat(Config ac_config)
	{
		this->m_Config = ac_config;
	}

	ANTICHEAT_INLINE Config GetConfig() { return this->m_Config; };

	ANTICHEAT_INLINE void CallbackOnceInit(std::function<void()> cb)
	{
		this->m_onceInit = cb;
	}

	ANTICHEAT_INLINE void SetDetectionCallbacks(DetectionCb cbs)
	{
		this->m_DetectionCallbacks = cbs;
	}

	ANTICHEAT_INLINE void AddDetectionCallback(std::function<void()> cb)
	{
		this->m_ProtectedThreads.push_back(std::make_pair(false, cb));
	}

	ANTICHEAT_INLINE ACSTATUS WINAPI Init()
	{
		LoadLibraryA("psapi.dll");
		LoadLibraryA("ntdll.dll");

		MH_Initialize();

		if (this->m_Config.threads_protection) {
			this->AddDetectionCallback([this] {
					this->ThreadsProtection(); // TODO: find a non messy way of checking if the thread protection thread has been closed..
				}
			);
		}

		if (this->m_Config.suspicious_threads)
		{
			this->AddDetectionCallback([this] {
				this->SuspiciousThreads();
				}
			);
		}

		if (this->m_Config.ldrloaddll_cb)
		{
			auto ldrloaddll_add = GetProcAddress(GetModuleHandleA("ntdll.dll"), "LdrLoadDll");

			if (const auto code = MH_CreateHook((LPVOID)ldrloaddll_add, &hooks::LdrLoadDll_HOOK, (LPVOID*)&hooks::original_ldrloaddll); code != MH_OK) {
				printf("an error occured while initializing ldrloaddll hook! %s\n", MH_StatusToString(code));
				return -1;
			}

			if (const auto code = MH_EnableHook(ldrloaddll_add); code != MH_OK)
			{
				printf("an error occured while initializing ldrloaddll hook! %s\n", MH_StatusToString(code));
				return -1;
			}
		}

		if (this->m_Config.illegal_exception)
		{
			SetUnhandledExceptionFilter(exceptions_handler);
		}

		auto safe_threads = std::thread([this] {
			while (true)
			{
				for (auto& cb : this->m_ProtectedThreads)
				{
					if (!cb.first) 
					{
						std::thread([&] {
							this->m_ProtectedThreadsIds.push_back(GetCurrentThreadId());
							cb.second();
							this->m_ProtectedThreadsIds.erase(std::remove(this->m_ProtectedThreadsIds.begin(), this->m_ProtectedThreadsIds.end(), GetCurrentThreadId()), this->m_ProtectedThreadsIds.end());
							this->m_ProtectedThreads.pop_back();
						}).detach();

						cb.first = true;
					}
				}

				Sleep(1);
			}
		});

		safe_threads.detach();

		this->m_onceInit();
		return 1;
	}
};

static anticheat* g_Instance;

LONG WINAPI hooks::LdrLoadDll_HOOK(PWSTR SearchPath OPTIONAL, PULONG DllCharacteristics OPTIONAL, PUNICODE_STRING DllName, PVOID* BaseAddress) // https://gist.github.com/bats3c/59932dfa1f5bb23dd36071119b91af0f
{
	auto ret = g_Instance->m_DetectionCallbacks.ldrloadllCb(DllName->Buffer);
	return ret ? 0 : static_cast<LONG(__thiscall*)(PWSTR, PULONG, PUNICODE_STRING, PVOID*)>(hooks::original_ldrloaddll)(SearchPath, DllCharacteristics, DllName, BaseAddress);
}

LONG WINAPI exceptions_handler(_EXCEPTION_POINTERS* ExceptionInfo)
{
	if (!IsMemoryInModuledRange(ExceptionInfo->ExceptionRecord->ExceptionAddress) || ExceptionInfo->ExceptionRecord->ExceptionCode == EXCEPTION_ACCESS_VIOLATION)
	{
		g_Instance->m_DetectionCallbacks.outsideModException();
	}

	return EXCEPTION_CONTINUE_SEARCH;
}