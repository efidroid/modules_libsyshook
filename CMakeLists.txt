cmake_minimum_required(VERSION 2.8)
project(multiboot C ASM)
set(CMAKE_BUILD_TYPE Release)


set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wshadow")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -static-libgcc -Wl,-static")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ffunction-sections -fdata-sections -Wl,-gc-sections -Os -s")

add_definitions(-DSYSHOOK_INTERNAL)

# main
add_library(syshook
    src/syshook.c
    src/defaults.c
    src/arch/arm/arch.c
    src/arch/arm/injections.S
)
include_directories(
    include
    include_private
)
