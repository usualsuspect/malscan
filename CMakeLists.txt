cmake_minimum_required (VERSION 3.8)

project ("malscan")

set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} /MT")

link_directories("libyara")
include_directories("include")
include_directories("libyara/include")

add_subdirectory("yarapp")
add_subdirectory ("malscan")
