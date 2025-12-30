cmake_minimum_required(VERSION 3.20)

# Project
project(jwt-cpp LANGUAGES CXX)

# --- Options ---------------------------------------------------------------
option(JWT_WARNINGS_AS_ERRORS "Treat warnings as errors" OFF)
option(JWT_USE_SYSTEM_GTEST "Prefer system-installed GTest if available" ON)
option(JWT_ENABLE_ASAN "Enable AddressSanitizer" OFF)
option(JWT_ENABLE_UBSAN "Enable UndefinedBehaviorSanitizer" OFF)
option(JWT_ENABLE_HARDENING "Enable security hardening flags" ON)

# --- Global settings -------------------------------------------------------
set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_POSITION_INDEPENDENT_CODE ON)
include(GNUInstallDirs)

# Helpful warnings (compiler-specific)
if (MSVC)
    add_compile_options(/W4)
    if (JWT_WARNINGS_AS_ERRORS)
        add_compile_options(/WX)
    endif()
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
    if (JWT_WARNINGS_AS_ERRORS)
        add_compile_options(-Werror)
    endif()
endif()

# --- Sanitizers ------------------------------------------------------------
if (JWT_ENABLE_ASAN)
    if (MSVC)
        add_compile_options(/fsanitize=address)
        add_link_options(/fsanitize=address)
    else()
        add_compile_options(-fsanitize=address -fno-omit-frame-pointer)
        add_link_options(-fsanitize=address)
    endif()
    message(STATUS "AddressSanitizer enabled")
endif()

if (JWT_ENABLE_UBSAN)
    if (NOT MSVC)
        add_compile_options(-fsanitize=undefined -fno-omit-frame-pointer)
        add_link_options(-fsanitize=undefined)
        message(STATUS "UndefinedBehaviorSanitizer enabled")
    else()
        message(WARNING "UndefinedBehaviorSanitizer not supported on MSVC")
    endif()
endif()

# --- Security Hardening Flags ----------------------------------------------
if (JWT_ENABLE_HARDENING AND NOT MSVC)
    # Stack protection
    add_compile_options(-fstack-protector-strong)

    # Fortify source (requires -O1 or higher)
    if (CMAKE_BUILD_TYPE STREQUAL "Release" OR CMAKE_BUILD_TYPE STREQUAL "RelWithDebInfo")
        add_compile_definitions(_FORTIFY_SOURCE=2)
    endif()

    # Position independent execution (PIE) for executables - Linux only
    if (CMAKE_SYSTEM_NAME STREQUAL "Linux")
        add_link_options(-Wl,-z,relro,-z,now)
    endif()

    message(STATUS "Security hardening flags enabled")
endif()

# --- Dependencies ----------------------------------------------------------

# Find nkeys-cpp (required dependency)
find_package(nkeys QUIET)
if (NOT nkeys_FOUND)
    # Try to find nkeys library manually
    find_library(NKEYS_LIBRARY NAMES nkeys libnkeys)
    find_path(NKEYS_INCLUDE_DIR nkeys/nkeys.hpp)

    if (NKEYS_LIBRARY AND NKEYS_INCLUDE_DIR)
        message(STATUS "Found nkeys: ${NKEYS_LIBRARY}")
        add_library(nkeys STATIC IMPORTED)
        set_target_properties(nkeys PROPERTIES
            IMPORTED_LOCATION "${NKEYS_LIBRARY}"
            INTERFACE_INCLUDE_DIRECTORIES "${NKEYS_INCLUDE_DIR}"
        )
    else()
        message(FATAL_ERROR "nkeys-cpp library not found. Please install from /Users/steve/src/nkeys-cpp or https://github.com/steve-weiland/nkeys-cpp")
    endif()
endif()

# Fetch nlohmann/json (header-only)
include(FetchContent)
FetchContent_Declare(
    nlohmann_json
    URL https://github.com/nlohmann/json/releases/download/v3.11.3/json.tar.xz
    URL_HASH SHA256=d6c65aca6b1ed68e7a182f4757257b107ae403032760ed6ef121c9d55e81757d
    DOWNLOAD_EXTRACT_TIMESTAMP TRUE
)
FetchContent_MakeAvailable(nlohmann_json)

# --- Sources ---------------------------------------------------------------
set(JWT_SOURCES
    src/jwt.cpp
    src/claims.cpp
    src/operator_claims.cpp
    src/account_claims.cpp
    src/user_claims.cpp
)

# --- Library: jwt ----------------------------------------------------------
add_library(jwt STATIC
    ${JWT_SOURCES}
)

target_include_directories(jwt PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/include
)
target_include_directories(jwt PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/src
)

target_link_libraries(jwt PUBLIC nkeys nlohmann_json::nlohmann_json)

# --- Executable: jwt++ -----------------------------------------------------
add_executable(jwt++ src/tools/jwt-main.cpp)
target_link_libraries(jwt++ PRIVATE jwt)
target_include_directories(jwt++ PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src/tools
)

# --- Tests: jwt_test (GoogleTest) ------------------------------------------
include(CTest)
if (BUILD_TESTING)
    # Threads are needed by GTest on POSIX
    find_package(Threads REQUIRED)

    set(_have_gtest FALSE)
    if (JWT_USE_SYSTEM_GTEST)
        find_package(GTest QUIET)
        if (GTest_FOUND)
            set(_have_gtest TRUE)
        endif()
    endif()

    if (NOT _have_gtest)
        include(FetchContent)
        FetchContent_Declare(
            googletest
            URL https://github.com/google/googletest/archive/refs/tags/v1.14.0.zip
            URL_HASH SHA256=1f357c27ca988c3f7c6b4bf68a9395005ac6761f034046e9dde0896e3aba00e4
            DOWNLOAD_EXTRACT_TIMESTAMP TRUE
        )
        # For MSVC: don't override runtime flags in gtest
        set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
        FetchContent_MakeAvailable(googletest)
        set(GTEST_LIBS GTest::gtest GTest::gtest_main)
    else()
        set(GTEST_LIBS GTest::GTest GTest::Main)
    endif()

    add_executable(jwt_test tests/jwt_test.cpp)
    target_link_libraries(jwt_test PRIVATE jwt ${GTEST_LIBS} Threads::Threads)
    target_include_directories(jwt_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

    add_executable(claims_test tests/claims_test.cpp)
    target_link_libraries(claims_test PRIVATE jwt ${GTEST_LIBS} Threads::Threads)
    target_include_directories(claims_test PRIVATE ${CMAKE_CURRENT_SOURCE_DIR}/include)

    add_executable(cmd_args_test tests/cmd_args_test.cpp)
    target_link_libraries(cmd_args_test PRIVATE ${GTEST_LIBS} Threads::Threads)
    target_include_directories(cmd_args_test PRIVATE
        ${CMAKE_CURRENT_SOURCE_DIR}/src/tools
        ${CMAKE_CURRENT_SOURCE_DIR}/tests
    )

    include(GoogleTest)
    gtest_discover_tests(jwt_test)
    gtest_discover_tests(claims_test)
    gtest_discover_tests(cmd_args_test)
endif()

# --- Install targets -------------------------------------------------------

# Install static library
install(TARGETS jwt
    ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR}
    LIBRARY DESTINATION ${CMAKE_INSTALL_LIBDIR}
)

# Install public headers - preserve include/jwt/ directory structure
install(FILES
    ${CMAKE_CURRENT_SOURCE_DIR}/include/jwt/jwt.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/jwt/jwt_constants.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/jwt/claims.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/jwt/operator_claims.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/jwt/account_claims.hpp
    ${CMAKE_CURRENT_SOURCE_DIR}/include/jwt/user_claims.hpp
    DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/jwt
)

# Install CLI tool executable
install(TARGETS jwt++
    RUNTIME DESTINATION ${CMAKE_INSTALL_BINDIR}
)
