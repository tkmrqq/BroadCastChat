cmake_minimum_required(VERSION 3.27)
project(BroadCastChat)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_EXE_LINKER_FLAGS "-static")
set(BUILD_SHARED_LIBS OFF)

if(WIN32)
    set(CMAKE_CXX_FLAGS "-static -static-libgcc -static-libstdc++")
    set(CMAKE_C_FLAGS "-static -static-libgcc")

    add_definitions(-D_WIN32_WINNT=0x0601)
    set(PLATFORM_LIBS ws2_32 iphlpapi)
else()
    set(PLATFORM_LIBS)
endif()

add_executable(BroadCastChat
        main.cpp
        cpp/core/network_utils.cpp
        cpp/core/p2p_chat.cpp
)

target_link_libraries(BroadCastChat ${PLATFORM_LIBS})