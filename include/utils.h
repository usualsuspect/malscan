#pragma once
#include <TlHelp32.h>
#include <vector>

namespace utils
{
	std::vector<PROCESSENTRY32> list_processes();
};