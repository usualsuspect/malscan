#include <iostream>

#include "yarapp.h"

#include <fstream>
#include <sstream>
#include <vector>
#include <Psapi.h>
#include <TlHelp32.h>

std::string read_file(const std::string& file_name)
{
	std::ifstream f(file_name);
	std::stringstream str;
	str << f.rdbuf();
	return str.str();
}

void yara_test()
{
	yarapp y;

	auto rule = read_file("rule.yara");

	try
	{
		std::cout << rule << std::endl;
		y.add_string(rule);
		y.finalize();
		//FIXME
		y.scan_memory((unsigned char *)0, 100);
	}
	catch (std::exception& e)
	{
		std::cerr << "Failed: " << e.what() << std::endl;
	}
}

auto list_processes()
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
	return processes;
}

void scan_process(DWORD pid)
{
	MEMORY_BASIC_INFORMATION mbi;
	DWORD addr = 0;
	VirtualQuery(&addr, &mbi, sizeof(MEMORY_BASIC_INFORMATION));

	do
	{
		std::cout << "AllocationBase: " << std::hex << mbi.AllocationBase << std::endl;
		std::cout << "RegionSize    : " << std::hex << mbi.RegionSize << std::endl;
		std::cout << "Base Address  : " << std::hex << mbi.BaseAddress << std::endl;

		addr = (DWORD)mbi.BaseAddress;
		addr += mbi.RegionSize;
	} while (VirtualQuery((LPCVOID)addr, &mbi, sizeof(MEMORY_BASIC_INFORMATION)));

	std::cout << "Bla: " << std::hex << mbi.AllocationBase << " Size: " << mbi.RegionSize << std::endl;
}

int main()
{
	for (auto& pe : list_processes())
	{
		std::cout << pe.szExeFile << std::endl;
		scan_process(pe.th32ProcessID);
		break;
	}
	system("PAUSE");
	return 0;
}
