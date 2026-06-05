# ===========================================================================
# git-crypt -- Windows / MSVC build (x64, static CRT, no external deps)
#
# This file lives OUTSIDE the upstream tree (win-build/) so syncing upstream
# never conflicts with it. It compiles the upstream sources from the parent
# directory, substitutes the Windows-native BCrypt crypto backend for the
# OpenSSL one, and statically links the MSVC CRT so the resulting exe needs
# no VC++ redistributable and no OpenSSL.
#
# Build via win-build\build.cmd (recommended) or build.ps1 -- those scripts
# load the Visual Studio x64 developer environment before invoking CMake.
# ===========================================================================

cmake_minimum_required(VERSION 3.20)

# CMP0091: let CMAKE_MSVC_RUNTIME_LIBRARY pick /MT vs /MD. Must be set before
# project() so the toolchain test compiles with the right runtime.
cmake_policy(SET CMP0091 NEW)

project(git-crypt-win LANGUAGES CXX)

if (NOT MSVC)
    message(FATAL_ERROR "This CMakeLists.txt targets MSVC only. For Unix builds use the upstream Makefile.")
endif()

set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release CACHE STRING "" FORCE)
endif()

# Static-link the CRT: /MT (Release) or /MTd (Debug). This is the "no MSVC
# runtime required" guarantee -- the exe carries the CRT inside it.
set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")

# Upstream source tree is one level up.
set(SRC_ROOT "${CMAKE_CURRENT_SOURCE_DIR}/..")

# Upstream sources. util.cpp / coprocess.cpp #include their *-win32.cpp halves
# under _WIN32, so we list only the dispatchers (mirrors the upstream Makefile's
# OBJFILES). crypto-openssl-11.cpp is intentionally excluded -- replaced below.
add_executable(git-crypt
    "${SRC_ROOT}/git-crypt.cpp"
    "${SRC_ROOT}/commands.cpp"
    "${SRC_ROOT}/crypto.cpp"
    "${SRC_ROOT}/gpg.cpp"
    "${SRC_ROOT}/key.cpp"
    "${SRC_ROOT}/util.cpp"
    "${SRC_ROOT}/parse_options.cpp"
    "${SRC_ROOT}/coprocess.cpp"
    "${SRC_ROOT}/fhstream.cpp"
    "${CMAKE_CURRENT_SOURCE_DIR}/crypto-win32.cpp"   # BCrypt backend (replaces crypto-openssl-11.cpp)
)

target_include_directories(git-crypt PRIVATE "${SRC_ROOT}")

target_compile_definitions(git-crypt PRIVATE
    WIN32_LEAN_AND_MEAN
    NOMINMAX                    # keep windows.h min/max macros from shadowing std::min/std::max
    _CRT_SECURE_NO_WARNINGS     # allow rename/getenv/etc. without _s nagging
    _CRT_NONSTDC_NO_DEPRECATE   # allow POSIX names: access(), unlink()
)

# /utf-8: source + execution charset UTF-8 (the help text is ASCII, but this
# keeps MSVC from guessing the codepage). /EHsc: standard C++ exceptions.
target_compile_options(git-crypt PRIVATE /utf-8 /EHsc /W3)

# bcrypt.dll (crypto) and advapi32.dll (process token + ACL APIs used to lock
# down key files / temp files to the current user) are Windows system
# components -- linking them adds no redistributable.
target_link_libraries(git-crypt PRIVATE bcrypt advapi32)

set_target_properties(git-crypt PROPERTIES
    RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin"
)
