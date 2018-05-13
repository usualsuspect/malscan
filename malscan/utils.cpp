#include <Windows.h>
#include "utils.h"

std::vector<PROCESSENTRY32> utils::list_processes()
{
	HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
	PROCESSENTRY32 pe;

	pe.dwSize = sizeof(PROCESSENTRY32);
	Process32First(snap, &pe);
	std::vector<PROCESSENTRY32> processes;
	do
	{
		processes.push_back(pe);
	} while (Process32Next(snap, &pe));
	CloseHandle(snap);
	return processes;
}