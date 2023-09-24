cmake_minimum_required(VERSION 3.24)
project(data_encryption C)

set(CMAKE_C_STANDARD 17)

find_package(SQLite3 REQUIRED)

add_executable(data_encryption main.c)

target_link_libraries(data_encryption ssl crypto SQLite::SQLite3)
