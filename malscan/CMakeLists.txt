cmake_minimum_required (VERSION 3.8)

link_directories("../libyara")
include_directories("../libyara/include")

add_executable (malscan "malscan.cpp" "yarapp.cpp")
target_link_libraries(malscan libyara32)