#include <Windows.h>
#include <utils.h>

#include <fstream>
#include <sstream>

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

std::string utils::read_file(const std::string& file_name)
{
	std::ifstream f(file_name);
	if (!f)
		return "";
	std::stringstream str;
	str << f.rdbuf();
	return str.str();
}

std::vector<unsigned char> utils::read_memory(HANDLE process, uintptr_t addr, size_t len)
{
	std::vector<unsigned char> data(len);
	SIZE_T read;
	ReadProcessMemory(process, reinterpret_cast<LPCVOID>(addr), data.data(), len, &read);
	return data;
}
