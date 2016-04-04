cmake_minimum_required(VERSION 2.8)
project(multiboot)
set(CMAKE_BUILD_TYPE Release)


set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wall -Wextra -Wshadow")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -static-libgcc -Wl,-static")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -ffunction-sections -fdata-sections -Wl,-gc-sections -Os -s")

add_definitions(-DSYSHOOK_INTERNAL)

# main
add_executable(init
    src/syshook.c
    src/arch/arm/arch.c

    # main code
    src/main.c
)
target_link_libraries(init pthread)
include_directories(
    include
    include_private
)
