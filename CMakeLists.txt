# This file is maintained by zkg. Do not edit.
# Put required additional cmake functionality into plugin.cmake.
cmake_minimum_required(VERSION 3.15.0 FATAL_ERROR)

project(ZeekPluginPerfSupport)

# Establish version numbers in config.h
file(STRINGS "${CMAKE_CURRENT_SOURCE_DIR}/VERSION" VERSION LIMIT_COUNT 1)

string(REGEX REPLACE "[.-]" " " version_numbers ${VERSION})
separate_arguments(version_numbers)
list(GET version_numbers 0 VERSION_MAJOR)
list(GET version_numbers 1 VERSION_MINOR)
list(GET version_numbers 2 VERSION_PATCH)

configure_file("${CMAKE_CURRENT_SOURCE_DIR}/src/config.h.in"
    "${CMAKE_CURRENT_BINARY_DIR}/config.h" @ONLY)

# Process any package-specific customizations
include(plugin.cmake OPTIONAL)

include(ZeekPlugin)

zeek_add_plugin(
    Zeek
    PerfSupport
    SOURCES
    src/Plugin.cc
    src/Trampoline.S
    DIST_FILES
    README.md
    CHANGES
    COPYING
    VERSION
)

set_source_files_properties(src/Trampoline.S PROPERTIES LANGUAGE C)

# Set -fno-omit-frame-pointer on the target for this plugin, or the stack is
# borked. Zeek also needs to be compiled that way. We set this as a file instead
# of a target property so it works regardless of whether the plugin is built
# standalone, or as a Zeek builtin plugin.
set_source_files_properties(src/Trampoline.S src/Plugin.cc PROPERTIES
    COMPILE_OPTIONS "-fno-omit-frame-pointer;-mno-omit-leaf-frame-pointer")

if ("${PROJECT_SOURCE_DIR}" STREQUAL "${CMAKE_SOURCE_DIR}")
    # Allows building rpm/deb packages via "make package" in build dir.
    include(ConfigurePackaging)
    ConfigurePackaging(${VERSION})
endif ()
