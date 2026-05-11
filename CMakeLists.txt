cmake_minimum_required(VERSION 4.0)
project(showeo)

set(CMAKE_CXX_STANDARD 20)

add_executable(showeo main.cpp
        include/library/x64dis.hpp
        include/library/x64decomp.h
        include/src/x64decomp.cpp
        include/src/x64dis.cpp)
