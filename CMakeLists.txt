cmake_minimum_required(VERSION 3.17)
project(ISA_proj)

set(CMAKE_CXX_STANDARD 14)

add_executable(ISA_proj main.cpp ErrorExceptions.h main.h DNS_Filter.cpp DNS_Filter.h)