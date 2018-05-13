#include <Python.h>
#include <iostream>

#include <utils.h>
#include <memory_scanner.h>

#include <fstream>
#include <sstream>
#include <vector>
#include <Psapi.h>


struct match_info_blub
{
	std::string identifier;
	std::vector<int64_t> offsets;
};

std::vector<match_info_blub> get_match_info(YR_RULE *rule)
{
	YR_STRING *str;
	std::vector<match_info_blub> matches;

	yr_rule_strings_foreach(rule, str)
	{
		match_info_blub mi;
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
	/*
	scan_info *si = reinterpret_cast<scan_info *>(user_data);
	YR_RULE *rule = reinterpret_cast<YR_RULE*>(msg_data);

	if (message == CALLBACK_MSG_RULE_MATCHING)
	{
		auto matches = get_match_info(rule);
		for (auto& match : matches)
			std::cout << "  Identifier " << match.identifier << " has " << match.offsets.size() << " matches." << std::endl;
	}
	*/
	return CALLBACK_CONTINUE;
}

int main()
{
	memory_scanner ms;
	try
	{
		std::cerr << "Loading rules..." << std::endl;
		ms.add_rule_file("rules.yara");

		ms.load_plugin("myplugin");

		std::cerr << "Scanning processes...." << std::endl;
		ms.scan_processes();
	}
	catch (std::exception& e)
	{
		std::cerr << "Error: " << e.what() << std::endl;
	}

	/*
	Py_Initialize();
	
	//Super weird: If we use "test" instead of plugin, the module will load, but "callme" won't be found when
	//running on Windows XP.
	//Solution from: https://stackoverflow.com/questions/24313681/pyobject-getattrstring-c-function-returning-null-unable-to-call-python-functi
	//wtf.
	*/
	system("PAUSE");
	return 0;
}
