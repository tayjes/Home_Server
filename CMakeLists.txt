cmake_minimum_required(VERSION 3.12)
project(pybind11_ip_scanner)

# Set C++ standard
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# Generate compile_commands.json for VS Code
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

# Find Python and pybind11
find_package(Python3 REQUIRED COMPONENTS Interpreter Development)

# Manually set pybind11 path
set(pybind11_DIR "${CMAKE_SOURCE_DIR}/venv/lib/python3.12/site-packages/pybind11/share/cmake/pybind11")
find_package(pybind11 REQUIRED)

# Original example module
pybind11_add_module(scan main.cpp)

#Output file location
set_target_properties(scan PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY
    "${CMAKE_SOURCE_DIR}/venv/lib64/python3.12/site-packages"
)
