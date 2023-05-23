cmake_minimum_required(VERSION 3.25)
project(ciphers)

set(CMAKE_CXX_STANDARD 17)

# Import Abseil's CMake targets
find_package(absl REQUIRED PATHS ~/Source/CMakeProject/install)
# sudo apt-get install libssl-dev
# The libssl-dev package is needed to provide FindOpenSSL.cmake
find_package(OpenSSL REQUIRED)

add_executable(ciphers main.cpp)
target_link_libraries(ciphers absl::strings OpenSSL::SSL OpenSSL::Crypto)