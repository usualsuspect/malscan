#pragma once

#include <Windows.h>
#include <TlHelp32.h>
#include <vector>
#include <string>

namespace utils
{
	std::vector<PROCESSENTRY32>		list_processes();
	std::string						read_file(const std::string& file_name);
	std::vector<unsigned char>		read_memory(HANDLE process, uintptr_t addr, size_t len);
};