cmake_minimum_required(VERSION 2.8)
project(multiboot C ASM)
set(CMAKE_BUILD_TYPE Release)

# generate syscall header
execute_process(
    COMMAND ${CMAKE_SOURCE_DIR}/gen_syscall_header ${EFIDROID_CONFIG_PATH} ${CMAKE_BINARY_DIR}
    OUTPUT_VARIABLE STDOUT
)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wshadow")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -static-libgcc -Wl,-static")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ffunction-sections -fdata-sections -Wl,-gc-sections -Os -s")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Werror")

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
    ${TARGET_MULTIBOOT_DIR}/include
    ${CMAKE_BINARY_DIR}/include
    ${CMAKE_BINARY_DIR}/include_private
)
