cmake_minimum_required(VERSION 3.5)

project(proxis VERSION 2.1.1)

set(CMAKE_C_STANDARD 99)
set(CMAKE_VERBOSE_MAKEFILE ON)

add_subdirectory(src)
add_subdirectory(test)
