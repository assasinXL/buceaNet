cmake_minimum_required(VERSION 3.10.0)

project(buceaNet)

set(EXECUTABLE_OUTPUT_PATH ${CMAKE_SOURCE_DIR}/bin)

find_package(cpr CONFIG REQUIRED)
add_executable(${PROJECT_NAME} 
src/main.cc 
src/sha1.cpp
src/md5.cpp
src/base64.cpp
)
target_link_libraries(${PROJECT_NAME} PRIVATE cpr)
