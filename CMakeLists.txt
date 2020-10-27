cmake_minimum_required(VERSION 3.17)
project(ISA_proj)

set(CMAKE_CXX_STANDARD 14)
SET(CMAKE_MODULE_PATH "/home/awesome/FIT/ISA/ISA_proj")
set("-pthread")

include(FindPCAP.cmake)
find_package(PCAP REQUIRED)

add_executable(ISA_proj  main.cpp ErrorExceptions.h DNS_Filter.cpp DNS_Filter.h common.h)
target_link_libraries(ISA_proj ${PCAP_LIBRARY} )
