#define STRICT
#define WIN32_LEAN_AND_MEAN
#include <Windows.h>
#include <TlHelp32.h>
#include <Psapi.h>
#pragma comment(lib, "Psapi.lib")

#include <vector>
#include <stdio.h>

std::vector<MEMORY_BASIC_INFORMATION> get_regions(HANDLE hProcess)
{
	void *lpAddress = NULL;
	MEMORY_BASIC_INFORMATION meminfo;

	DWORD dwExecutable = PAGE_EXECUTE | PAGE_EXECUTE_READ | PAGE_EXECUTE_READWRITE | PAGE_EXECUTE_WRITECOPY;

	std::vector<MEMORY_BASIC_INFORMATION> regions;

	for (;;)
	{
		if (VirtualQueryEx(hProcess, lpAddress, &meminfo, sizeof(meminfo)) == 0)
			break;

		lpAddress = (void *)((LONG_PTR)meminfo.BaseAddress + meminfo.RegionSize);

		if (meminfo.Protect & dwExecutable) 
			regions.push_back(meminfo); 
	}

	return regions;
}

std::vector<MODULEINFO> get_modules(HANDLE hProcess)
{
	HMODULE hMods[1024];
	DWORD cbNeeded;

	std::vector<MODULEINFO> modules;

	if (EnumProcessModulesEx(hProcess, hMods, sizeof(hMods), &cbNeeded, LIST_MODULES_ALL))
	{
		size_t i;
		for (i = 0; i < (cbNeeded / sizeof(HMODULE)); ++i)
		{
			MODULEINFO modinfo;
			if (GetModuleInformation(hProcess, hMods[i], &modinfo, sizeof(modinfo)))
				modules.push_back(modinfo);
		}
	}

	return modules;
}

std::vector<CONTEXT> get_threads(DWORD dwPid)
{
	HANDLE h = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);

	std::vector<CONTEXT> threads;

	if (h != INVALID_HANDLE_VALUE) 
	{
		THREADENTRY32 te;
		te.dwSize = sizeof(te);

		if (Thread32First(h, &te)) 
		{
			do 
			{
				if (te.th32OwnerProcessID == dwPid)
				{
					CONTEXT context = { 0 };
					context.ContextFlags = CONTEXT_FULL;

					HANDLE hThread = OpenThread(THREAD_ALL_ACCESS, FALSE, te.th32ThreadID);

					SuspendThread(hThread);

					if (GetThreadContext(hThread, &context))
						threads.push_back(context);

					DWORD dwError = GetLastError();

					ResumeThread(hThread);
				}
				te.dwSize = sizeof(te); /* see: http://blogs.msdn.com/b/oldnewthing/archive/2006/02/23/537856.aspx */
			} while (Thread32Next(h, &te));
		}

		CloseHandle(h);
	}

	return threads;
}


void print_range(ULONG_PTR start, ULONG_PTR end)
{ 
	printf("0x%08x - 0x%08x\n", start, end);
}

int main(int argc, char *argv[])
{
	DWORD dwPid = 7668;//GetCurrentProcessId();
	HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwPid);
	 
	for (auto region : get_regions(hProcess))
		print_range((ULONG_PTR)region.BaseAddress, (ULONG_PTR)region.BaseAddress + region.RegionSize); 

	printf("\nDLLs:\n"); 

	for (auto module : get_modules(hProcess))
		print_range((ULONG_PTR)module.lpBaseOfDll, (ULONG_PTR)module.lpBaseOfDll + (ULONG_PTR)module.lpBaseOfDll);

	printf("\nThreads:\n");
	for (auto thread : get_threads(dwPid))
		print_range((ULONG_PTR)thread.Eip, (ULONG_PTR)thread.Esp);

	getchar();
	return 0;
}
