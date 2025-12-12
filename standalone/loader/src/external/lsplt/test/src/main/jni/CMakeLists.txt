cmake_minimum_required(VERSION 3.18.1)
project("lsplt_test")

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

add_library(test SHARED test.cpp)
find_package(lsplt REQUIRED CONFIG)
target_link_libraries(test log lsplt::lsplt)
