cmake_minimum_required (VERSION 3.8)

find_package(PythonLibs 3.4 REQUIRED)

set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_STATIC_RUNTIME ON)
find_package(Boost 1.67 REQUIRED COMPONENTS program_options filesystem)

include_directories("${PYTHON_INCLUDE_DIRS}")

add_executable (malscan "malscan.cpp" "utils.cpp" "python_plugin.cpp" "memory_scanner.cpp")

target_link_libraries(malscan Boost::program_options Boost::filesystem)
target_link_libraries(malscan yarapp "${PYTHON_LIBRARIES}")
