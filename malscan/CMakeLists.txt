cmake_minimum_required (VERSION 3.8)

find_package(PythonLibs 3.4 REQUIRED)

include_directories("${PYTHON_INCLUDE_DIRS}")

add_executable (malscan "malscan.cpp" "utils.cpp" "python_plugin.cpp" "memory_scanner.cpp")
target_link_libraries(malscan yarapp "${PYTHON_LIBRARIES}")
