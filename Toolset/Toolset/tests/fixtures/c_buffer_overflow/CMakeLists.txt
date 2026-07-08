cmake_minimum_required(VERSION 3.13)
project(toolset_c_buffer_overflow C)

add_executable(vuln vuln.c)
enable_testing()
add_test(NAME normal_input COMMAND vuln)
