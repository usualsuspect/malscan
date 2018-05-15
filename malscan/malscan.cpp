#include <iostream>
#include <memory_scanner.h>

#include <boost/filesystem.hpp>
#include <boost/program_options.hpp>

namespace bfs = boost::filesystem;

void setup(memory_scanner& ms)
{
    bfs::path plugin_dir("plugins");
    if (!bfs::is_directory(plugin_dir))
        throw std::runtime_error("Plugin directory not found");

    bfs::path rule_dir("rules");
    if (!bfs::is_directory(rule_dir))
        throw std::runtime_error("Rule directory not found");

    for (bfs::directory_iterator it(plugin_dir); it != bfs::directory_iterator(); ++it)
    {
        if (it->path().extension() != ".py")
            continue;

        auto plugin = bfs::basename(it->path());
        std::cout << "Loading plugin " << plugin << std::endl;
        ms.load_plugin("plugins."+plugin);
    }

    for (bfs::directory_iterator it(rule_dir); it != bfs::directory_iterator(); ++it)
    {
        if (it->path().extension() != ".yara")
            continue;
        std::cout << "Loading rule " << it->path().string() << std::endl;
        ms.add_rule_file(it->path().string());
    }
}

int main(int argc, char **argv)
{
    memory_scanner ms;
    try
    {
        setup(ms);
        ms.scan_processes();
    }
    catch (std::exception& e)
    {
        std::cerr << "Error: " << e.what() << std::endl;
    }
    system("PAUSE");
    return 0;
}
