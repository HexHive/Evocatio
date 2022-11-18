project(bug-severity-lib)
#cmake_minimum_required(VERSION 3.21)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -Werror")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")
add_subdirectory(asan)
