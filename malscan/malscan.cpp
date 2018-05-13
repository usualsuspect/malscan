#include <Python.h>
#include <iostream>

#include <yarapp.h>
#include <utils.h>

#include <fstream>
#include <sstream>
#include <vector>
#include <Psapi.h>

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

	std::cout << rule << std::endl;

	try
	{
		std::cout << rule << std::endl;
		y.add_string(rule);
		y.finalize();
	}
	catch (std::exception& e)
	{
		std::cerr << "Failed: " << e.what() << std::endl;
	}
}

std::vector<unsigned char> read_memory(HANDLE process, DWORD addr, size_t len)
{
	std::vector<unsigned char> data(len);
	SIZE_T read;
	ReadProcessMemory(process, (LPCVOID)addr, data.data(), len,&read);
	return data;
}

struct scan_info
{
	PROCESSENTRY32 pe;
	uintptr_t base_addr;
	SIZE_T size;
};

struct match_info
{
	std::string identifier;
	std::vector<int64_t> offsets;
};

std::vector<match_info> get_match_info(YR_RULE *rule)
{
	YR_STRING *str;
	std::vector<match_info> matches;

	yr_rule_strings_foreach(rule, str)
	{
		match_info mi;
		mi.identifier = str->identifier;

		YR_MATCH *match;
		yr_string_matches_foreach(str,match)
		{
			mi.offsets.push_back(match->offset);
		}
		matches.push_back(mi);
	}
	return matches;
}

int callback(int message, void *msg_data, void *user_data)
{
	scan_info *si = reinterpret_cast<scan_info *>(user_data);
	YR_RULE *rule = reinterpret_cast<YR_RULE*>(msg_data);

	if (message == CALLBACK_MSG_RULE_MATCHING)
	{
		auto matches = get_match_info(rule);
		for (auto& match : matches)
			std::cout << "  Identifier " << match.identifier << " has " << match.offsets.size() << " matches." << std::endl;
	}
	return CALLBACK_CONTINUE;
}

void scan_process(yarapp& y,PROCESSENTRY32& pe)
{
	HANDLE process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE,pe.th32ProcessID);
	if (!process)
		return;

	MEMORY_BASIC_INFORMATION mbi;
	uintptr_t addr = 0;
	VirtualQueryEx(process,(LPCVOID)0, &mbi, sizeof(MEMORY_BASIC_INFORMATION));

	size_t total = 0;

	do
	{
		if (mbi.State == MEM_COMMIT)
		{
			/*std::cout << "AllocationBase: " << std::hex << mbi.AllocationBase << std::endl;
			std::cout << "RegionSize    : " << std::hex << mbi.RegionSize << std::endl;
			std::cout << "Base Address  : " << std::hex << mbi.BaseAddress << std::endl;
			*/
			
			auto data = read_memory(process, (DWORD)mbi.AllocationBase, mbi.RegionSize);
			total += data.size();

			scan_info si;
			si.pe = pe;
			si.base_addr = reinterpret_cast<uintptr_t>(mbi.AllocationBase);
			si.size = mbi.RegionSize;

			y.scan_memory(data.data(), data.size(), reinterpret_cast<void*>(&si));
		}

		addr = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
		addr += mbi.RegionSize;
	} while (VirtualQueryEx(process,reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(MEMORY_BASIC_INFORMATION)));

	std::cout << "Scanned " << total << " bytes." << std::endl;

	CloseHandle(process);
}

void scan_test()
{
	yarapp y;
	auto rule = read_file("rule.yara");
	if (!read_file)
		return;

	std::cout << rule << std::endl;

	y.add_string(rule);
	y.finalize();
	y.set_scan_callback(callback);

	auto self_pid = GetCurrentProcessId();

	for (auto& pe : utils::list_processes())
	{
		if(pe.th32ProcessID != self_pid)
			scan_process(y, pe);
	}
}

int main()
{
	scan_test();
	/*
	Py_Initialize();
	
	//Super weird: If we use "test" instead of plugin, the module will load, but "callme" won't be found when
	//running on Windows XP.
	//Solution from: https://stackoverflow.com/questions/24313681/pyobject-getattrstring-c-function-returning-null-unable-to-call-python-functi
	//wtf.
	auto name = PyUnicode_DecodeFSDefault("plugin");
	auto module = PyImport_Import(name);
	if (!module)
	{
		char wd[1024];
		GetCurrentDirectory(sizeof(wd), wd);
		std::cerr << "Workign dir: " << wd << std::endl;

		std::cerr << "Import failed" << std::endl;
	}
	else
	{
		auto func = PyObject_GetAttrString(module, "callme");
		if (!func)
		{
			std::cerr << "Function not found!" << std::endl;
		}
		auto args = PyTuple_New(0);
		auto ret = PyObject_CallObject(func, args);

		if (ret)
		{
			std::cout << "Result: " << PyLong_AsLong(ret) << std::endl;
		}
	}
	*/
	system("PAUSE");
	return 0;
}
