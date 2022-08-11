cmake_minimum_required(VERSION 2.4)

project(dumpe)

include_directories(src)

add_library(libpe src/pe.c)
add_executable(dumpe src/main.c)

target_link_libraries(dumpe libpe)
