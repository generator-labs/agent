cmake_minimum_required(VERSION 3.10)
project(GeneratorAgent VERSION 1.0.0.0)

configure_file(version.h.in ${CMAKE_CURRENT_BINARY_DIR}/version.h)

if(NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

add_compile_options(-Wall)

include(CheckCXXCompilerFlag)
check_cxx_compiler_flag(-mavx2 HAS_AVX2)
if(HAS_AVX2 AND CMAKE_SYSTEM_PROCESSOR MATCHES "x86_64|AMD64")
    add_compile_options(-mavx2)
endif()

find_package(PkgConfig REQUIRED)
pkg_check_modules(JANSSON REQUIRED jansson)
pkg_check_modules(UUID REQUIRED uuid)

find_package(OpenSSL REQUIRED)
find_package(CURL REQUIRED)
find_package(Threads REQUIRED)

set(SOURCES
    agent.cpp
    lib/cagent.cpp
    lib/ccert_protocol.cpp
    lib/ctask_cert.cpp
    lib/ctask.cpp
    lib/ctask_manager.cpp
)

add_executable(agent ${SOURCES})

target_include_directories(agent PRIVATE ${JANSSON_INCLUDE_DIRS} ${CURL_INCLUDE_DIRS} ${UUID_INCLUDE_DIRS} ${CMAKE_CURRENT_SOURCE_DIR} ${CMAKE_CURRENT_SOURCE_DIR}/lib ${CMAKE_CURRENT_BINARY_DIR})

target_link_libraries(agent PRIVATE
    ${JANSSON_LIBRARIES}
    ${UUID_LIBRARIES}
    OpenSSL::SSL
    OpenSSL::Crypto
    CURL::libcurl
    Threads::Threads
)

# Testing support
option(BUILD_TESTS "Build unit tests" OFF)

if(BUILD_TESTS)
    include(FetchContent)
    FetchContent_Declare(
        googletest
        GIT_REPOSITORY https://github.com/google/googletest.git
        GIT_TAG v1.14.0
    )
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)

    enable_testing()

    # Library target for testable code (without main)
    add_library(agent_lib STATIC
        lib/cagent.cpp
        lib/ccert_protocol.cpp
        lib/ctask_cert.cpp
        lib/ctask.cpp
        lib/ctask_manager.cpp
    )
    target_include_directories(agent_lib PUBLIC
        ${JANSSON_INCLUDE_DIRS}
        ${CURL_INCLUDE_DIRS}
        ${UUID_INCLUDE_DIRS}
        ${CMAKE_CURRENT_SOURCE_DIR}
        ${CMAKE_CURRENT_SOURCE_DIR}/lib
        ${CMAKE_CURRENT_BINARY_DIR}
    )
    target_link_libraries(agent_lib PUBLIC
        ${JANSSON_LIBRARIES}
        ${UUID_LIBRARIES}
        OpenSSL::SSL
        OpenSSL::Crypto
        CURL::libcurl
        Threads::Threads
    )

    # Test executable
    add_executable(agent_tests
        tests/test_cexception.cpp
        tests/test_chttp.cpp
        tests/test_ctask_cert.cpp
        tests/test_ctask_manager.cpp
        tests/test_cagent.cpp
        tests/test_ccert_protocol.cpp
    )
    target_link_libraries(agent_tests PRIVATE
        agent_lib
        GTest::gtest_main
    )

    include(GoogleTest)
    gtest_discover_tests(agent_tests)
endif()
