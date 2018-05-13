#pragma once

#include <Windows.h>
#include <TlHelp32.h>

#include <yarapp.h>
#include <python_plugin.h>
#include <vector>

class memory_scanner
{
public:
    memory_scanner();
    ~memory_scanner();

    void add_rule_file(const std::string& file_name);
    void load_plugin(const std::string& name);

    //python_plugin(const python_plugin&) = delete;
    //python_plugin& operator=(const python_plugin&) = delete;

    memory_scanner(const memory_scanner& other) = delete;
    memory_scanner& operator=(const memory_scanner&) = delete;

    void scan_processes();
protected:
    int scan_callback(int, void *, void *);
    void scan_process(PROCESSENTRY32& pe);

    std::vector<std::string> find_plugins(const YR_RULE *rule) const;

    std::function<int(int, void*, void*)> temp;

    std::vector<python_plugin> plugins_;
    yarapp y_;
};