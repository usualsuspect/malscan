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

bool yarapp::add_string(const std::string& rule, const std::string& rule_namespace)
{
    if (!compiler_)
        return false;
    if (yr_compiler_add_string(compiler_, rule.c_str(), rule_namespace.c_str()) != 0)
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

/* FORGIVE ME FOR I HAVE SINNED*/
std::function<int(int, void *, void *)> ugly_target_hack;
int ugly_callback_hack(int msg, void *msg_data, void *user_data)
{
    //We cannot pass std::bind() return values to a plain C function pointer, so we need a mediator
    //using a global variable like BARBARIANS
    return ugly_target_hack(msg, msg_data, user_data);
}

void yarapp::scan_memory(unsigned char *buffer, size_t buffer_len, void *user_data)
{
    if (!rules_)
        finalize();

    if (ugly_target_hack)
        yr_rules_scan_mem(rules_, buffer, buffer_len, 0, ugly_callback_hack, user_data, 0);
}


void yarapp::set_scan_callback(std::function<int(int, void *, void *)> cb)
{
    ugly_target_hack = cb;
}