cmake_minimum_required(VERSION 3.17)
project(ISA_proj)

set(CMAKE_CXX_STANDARD 17)
SET(CMAKE_MODULE_PATH "/home/awesome/FIT/ISA/ISA_proj")
SET(CMAKE_CXX_FLAGS -pthread)

add_executable(ISA_proj  main.cpp ErrorExceptions.h DNSFilter.cpp DNSFilter.h logger.h logger.cpp DomainLookup.cpp DomainLookup.h)
