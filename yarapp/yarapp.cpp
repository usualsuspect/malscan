#include <yarapp.h>

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
	std::cout << "Dumping rule..." << std::endl;
	std::cout << "Rule: " << rule->identifier << std::endl;
}

void yarapp::scan_memory(unsigned char *buffer, size_t buffer_len,void *user_data)
{
	if (!rules_)
		finalize();

	if (scan_callback_)
	{
		typedef int(*scan_sb)(int, void *, void*);
		scan_sb *ptr = scan_callback_.target<scan_sb>();
		yr_rules_scan_mem(rules_, buffer, buffer_len, 0, *ptr, user_data, 0);
	}
	else
	{
	}
}

void yarapp::set_scan_callback(std::function<int(int, void *, void *)> cb)
{
	scan_callback_ = cb;
}