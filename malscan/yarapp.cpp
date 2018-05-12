#include "yarapp.h"

#include <iostream>

yarapp::yarapp() : compiler_(nullptr), rules_(nullptr)
{
	yr_initialize();
	yr_compiler_create(&compiler_);
}

yarapp::~yarapp()
{
	if (rules_)
		yr_rules_destroy(rules_);
	if (compiler_)
		yr_compiler_destroy(compiler_);
	yr_finalize();
}

bool yarapp::add_string(const std::string& rule)
{
	if (!compiler_)
		return false;
	if (yr_compiler_add_string(compiler_, rule.c_str(), "nonamespace") != 0)
		throw std::runtime_error("Failed to add rule");

	return true;
}

void yarapp::finalize()
{
	if (rules_)
		throw std::runtime_error("Rules already finalized");
	yr_compiler_get_rules(compiler_, &rules_);
}

void dump_rule(YR_RULE *rule)
{
	std::cout << "Rule: " << rule->identifier << std::endl;
}

int yarapp::scan_callback(int message, void *msg_data, void *user_data)
{
	switch (message)
	{
	case CALLBACK_MSG_RULE_MATCHING:
		std::cout << "Rule matched!" << std::endl;
		dump_rule(reinterpret_cast<YR_RULE*>(msg_data));
		break;
	case CALLBACK_MSG_RULE_NOT_MATCHING:
		std::cout << "Rule did NOT match!" << std::endl;
		dump_rule(reinterpret_cast<YR_RULE*>(msg_data));
		break;
	case CALLBACK_MSG_SCAN_FINISHED:
		std::cout << "Scan finished" << std::endl;
		break;
	default:
		std::cout << "Default" << std::endl;
		break;
	}
	return CALLBACK_CONTINUE;
}

void yarapp::scan_memory(unsigned char *buffer, size_t buffer_len)
{
	if (!rules_)
		finalize();

	yr_rules_scan_mem(rules_, buffer, buffer_len, 0, yarapp::scan_callback, nullptr, 0);
}