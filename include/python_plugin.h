#pragma once

#include <Python.h>
#include <string>
#include <vector>

struct string_match
{
    std::string identifier;
    std::vector<int64_t> offsets;
};

struct match_info
{
    std::string executable;
    unsigned int pid;
    uintptr_t addr;

    std::vector<string_match> matches;
    std::vector<unsigned char> *data;
};

class python_plugin
{
public:
    python_plugin(const std::string& name);
    ~python_plugin();

    python_plugin(const python_plugin&) = delete;
    python_plugin& operator=(const python_plugin&) = delete;

    //move
    python_plugin& operator=(python_plugin&& other);
    python_plugin(python_plugin&& other);

    bool operator==(const std::string& name) const { return name_ == name; }
    const std::string& name() const { return name_; }

    void on_match(const match_info&);

protected:
    PyObject * make_args(const match_info&);
    std::string name_;
    PyObject *module_;
    PyObject *match_func_;
};