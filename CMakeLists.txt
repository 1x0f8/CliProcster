cmake_minimum_required(VERSION 3.16)

project(CliProcster LANGUAGES CXX)

add_executable(CliProcster main.cpp src/observability_backends.cpp)
target_compile_features(CliProcster PRIVATE cxx_std_17)

if(WIN32)
  target_link_libraries(CliProcster PRIVATE Ws2_32)
endif()

if(MSVC)
  target_compile_options(CliProcster PRIVATE /W3)
else()
  target_compile_options(CliProcster PRIVATE -Wall -Wextra -pedantic)
endif()
