cmake_minimum_required(VERSION 3.12)
project(pybind11_ip_scanner)

set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

find_package(Python3 REQUIRED COMPONENTS Interpreter Development)

# Try venv Python first (local), fall back to system Python (Docker)
if(EXISTS "${CMAKE_SOURCE_DIR}/venv/bin/python3")
    set(PYBIND11_PYTHON "${CMAKE_SOURCE_DIR}/venv/bin/python3")
else()
    set(PYBIND11_PYTHON "${Python3_EXECUTABLE}")
endif()

execute_process(
    COMMAND "${PYBIND11_PYTHON}" -c "import pybind11; print(pybind11.get_cmake_dir())"
    OUTPUT_VARIABLE pybind11_DIR
    OUTPUT_STRIP_TRAILING_WHITESPACE
)

message(STATUS "pybind11_DIR resolved to: ${pybind11_DIR}")

find_package(pybind11 REQUIRED)

pybind11_add_module(scan lib/scanner/main.cpp)

set_target_properties(scan PROPERTIES
    LIBRARY_OUTPUT_DIRECTORY "${CMAKE_SOURCE_DIR}/lib"
)