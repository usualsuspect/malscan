cmake_minimum_required (VERSION 3.8)

include_directories("C:/Python34/include")
link_directories("C:/Python34/libs")

add_executable (malscan "malscan.cpp" "utils.cpp")
target_link_libraries(malscan yarapp Python34)
