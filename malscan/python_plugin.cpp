#include <python_plugin.h>

#include <iostream>

python_plugin::python_plugin(const std::string& name) : name_(name), module_(nullptr), match_func_(nullptr)
{
    auto plug_name = PyUnicode_DecodeFSDefault(name_.c_str());
    module_ = PyImport_Import(plug_name);
    Py_DECREF(plug_name);

    if (!module_)
    {
        PyErr_Print();
        throw std::runtime_error("Failed to load Python plugin " + name_ + ", aborting.");
    }

    match_func_ = PyObject_GetAttrString(module_, "on_match");
    if (!match_func_)
        std::cerr << "Warning: Plugin '" << name_ << "' contains no function 'on_match()'" << std::endl;
}

python_plugin& python_plugin::operator=(python_plugin&& other)
{
    match_func_ = other.match_func_;
    module_ = other.module_;
    name_ = other.name_;

    other.match_func_ = nullptr;
    other.module_ = nullptr;
    other.name_ = "";
    return *this;
}

python_plugin::python_plugin(python_plugin&& other)
{
    match_func_ = other.match_func_;
    module_ = other.module_;
    name_ = other.name_;

    other.match_func_ = nullptr;
    other.module_ = nullptr;
    other.name_ = "";
}

void python_plugin::on_match(const match_info& mi)
{
    if (match_func_ && PyCallable_Check(match_func_))
    {
        auto args = make_args(mi);
        PyObject_CallObject(match_func_, args);
        Py_DECREF(args);
    }
}

PyObject * python_plugin::make_args(const match_info &mi)
{
    auto args = PyTuple_New(2);

    auto match_dict = PyDict_New();
    for (auto& match : mi.matches)
    {
        auto match_addr_list = PyTuple_New(match.offsets.size());
        auto key = PyUnicode_FromString(match.identifier.c_str());

        for (size_t i = 0; i < match.offsets.size(); ++i)
        {
            auto off = PyLong_FromUnsignedLongLong(match.offsets[i]);
            PyTuple_SetItem(match_addr_list, i, off);
        }
        PyDict_SetItem(match_dict, key, match_addr_list);
    }

    auto val = Py_BuildValue("{s:s,s:i,s:i,s:O}",
        "executable", mi.executable.c_str(),
        "pid", mi.pid,
        "address", mi.addr,
        "matches", match_dict);

    auto data = PyBytes_FromStringAndSize(reinterpret_cast<const char *>(mi.data->data()), mi.data->size());
    PyTuple_SetItem(args, 0, val);
    PyTuple_SetItem(args, 1, data);

    return args;
}

python_plugin::~python_plugin()
{
    Py_XDECREF(match_func_);
    Py_XDECREF(module_);
}