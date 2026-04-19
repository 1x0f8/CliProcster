cmake_minimum_required(VERSION 3.16)

project(CliProcster LANGUAGES CXX)

add_executable(CliProcster main.cpp)
target_compile_features(CliProcster PRIVATE cxx_std_17)

if(MSVC)
  target_compile_options(CliProcster PRIVATE /W3)
else()
  target_compile_options(CliProcster PRIVATE -Wall -Wextra -pedantic)
endif()
