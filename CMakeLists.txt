cmake_minimum_required(VERSION 3.15)
project(byebyevpn CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

if(MSVC)
    add_compile_options(/W3 /O2 /utf-8)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS -DNOMINMAX -DWIN32_LEAN_AND_MEAN)
else()
    add_compile_options(-O2 -Wall -Wextra -Wno-unused-parameter -Wno-unused-function)
endif()

find_package(OpenSSL REQUIRED)

add_executable(byebyevpn src/byebyevpn.cpp)
target_link_libraries(byebyevpn PRIVATE OpenSSL::SSL OpenSSL::Crypto)

if(WIN32)
    target_link_libraries(byebyevpn PRIVATE ws2_32 iphlpapi winhttp crypt32 bcrypt dnsapi)
    target_compile_definitions(byebyevpn PRIVATE _WIN32_WINNT=0x0A00)
else()
    find_package(Threads REQUIRED)
    target_link_libraries(byebyevpn PRIVATE Threads::Threads)
endif()

install(TARGETS byebyevpn RUNTIME DESTINATION bin)
