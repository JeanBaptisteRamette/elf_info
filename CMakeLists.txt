cmake_minimum_required(VERSION 3.17)
project(elf_info)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED True)

set(INC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/include")
set(SRC_DIR "${CMAKE_CURRENT_SOURCE_DIR}/src")

file(GLOB SRC_FILES
        "${INC_DIR}/elf_info/*.hh"
        "${SRC_DIR}/*.cpp")

add_compile_options(-Wall -Wextra)
add_executable(elf_info ${SRC_FILES})
add_subdirectory(fmt EXCLUDE_FROM_ALL)

target_include_directories(elf_info PRIVATE fmt/include/ ${INC_DIR})
target_link_libraries(elf_info PRIVATE fmt::fmt)
