#include <memory_scanner.h>
#include <utils.h>
#include <functional>
#include <iostream>

memory_scanner::memory_scanner()
{
	yr_initialize();
	Py_Initialize();

	using namespace std::placeholders;

	y_.set_scan_callback(std::bind(&memory_scanner::scan_callback, this, _1, _2, _3));
}

memory_scanner::~memory_scanner()
{
	plugins_.clear();

	Py_Finalize();
	yr_finalize();
}

void memory_scanner::add_rule_file(const std::string & file_name)
{
	auto rule = utils::read_file(file_name);
	if (rule != "")
		y_.add_string(rule);
}

void memory_scanner::load_plugin(const std::string & name)
{
	std::cerr << "Loading plugin " << name << std::endl;
	plugins_.emplace_back(python_plugin(name));
}

void memory_scanner::scan_processes()
{
	y_.finalize();
	auto self_pid = GetCurrentProcessId();

	for (auto& pe : utils::list_processes())
	{
		if (pe.th32ProcessID != self_pid)
			scan_process(pe);
	}
}

std::vector<std::string> memory_scanner::find_plugins(const YR_RULE *rule) const
{
	std::vector<std::string> plugins;

	YR_META *meta;
	yr_rule_metas_foreach(rule, meta)
	{
		if (std::string(meta->identifier) == "plugin" && meta->type == META_TYPE_STRING)
			plugins.push_back(meta->string);
	}
	return plugins;
}

struct scan_info
{
	PROCESSENTRY32 pe;
	uintptr_t base_addr;
	SIZE_T size;

	std::vector<unsigned char> *data;
};

std::vector<string_match> get_match_info(YR_RULE *rule)
{
	YR_STRING *str;
	std::vector<string_match> matches;

	yr_rule_strings_foreach(rule, str)
	{
		string_match sm;
		sm.identifier = str->identifier;

		YR_MATCH *match;
		yr_string_matches_foreach(str, match)
		{
			sm.offsets.push_back(match->offset);
		}
		matches.push_back(sm);
	}
	return matches;
}

int memory_scanner::scan_callback(int message, void *msg_data, void *user_data)
{
	if (message == CALLBACK_MSG_RULE_MATCHING)
	{
		YR_RULE *rule = reinterpret_cast<YR_RULE *>(msg_data);
		scan_info *si = reinterpret_cast<scan_info *>(user_data);

		auto plugin_list = find_plugins(rule);

		if (plugin_list.size() > 0)
		{
			match_info mi;
			mi.matches = get_match_info(rule);
			mi.addr = si->base_addr;
			mi.pid = si->pe.th32ProcessID;
			mi.executable = si->pe.szExeFile;
			mi.data = si->data;

			for (auto& plug_name : plugin_list)
			{
				auto it = std::find(plugins_.begin(), plugins_.end(), plug_name);
				if (it != plugins_.end())
					it->on_match(mi);
			}
		}
	}
	return CALLBACK_ABORT;
}


void memory_scanner::scan_process(PROCESSENTRY32& pe)
{
	HANDLE process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pe.th32ProcessID);
	if (!process)
		return;

	MEMORY_BASIC_INFORMATION mbi;
	uintptr_t addr = 0;
	VirtualQueryEx(process, (LPCVOID)0, &mbi, sizeof(MEMORY_BASIC_INFORMATION));

	size_t total = 0;

	do
	{
		if (mbi.State == MEM_COMMIT)
		{
			/*std::cout << "AllocationBase: " << std::hex << mbi.AllocationBase << std::endl;
			std::cout << "RegionSize    : " << std::hex << mbi.RegionSize << std::endl;
			std::cout << "Base Address  : " << std::hex << mbi.BaseAddress << std::endl;
			*/

			auto data = utils::read_memory(process, reinterpret_cast<uintptr_t>(mbi.AllocationBase), mbi.RegionSize);
			total += data.size();

			scan_info si;
			si.pe = pe;
			si.base_addr = reinterpret_cast<uintptr_t>(mbi.AllocationBase);
			si.size = mbi.RegionSize;
			si.data = &data;

			y_.scan_memory(data.data(), data.size(), reinterpret_cast<void*>(&si));
		}

		addr = reinterpret_cast<uintptr_t>(mbi.BaseAddress);
		addr += mbi.RegionSize;
	} while (VirtualQueryEx(process, reinterpret_cast<LPCVOID>(addr), &mbi, sizeof(MEMORY_BASIC_INFORMATION)));
	CloseHandle(process);
}