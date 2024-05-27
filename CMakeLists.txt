cmake_minimum_required(VERSION 3.12)
project(cats-simulator)

include(FetchContent)
FetchContent_Declare(
    libCATS
    GIT_REPOSITORY https://github.com/CamK06/libCATS.git
)
FetchContent_Declare(
    flog
    GIT_REPOSITORY https://github.com/AlexandreRouma/flog.git
)
FetchContent_MakeAvailable(flog libCATS)

file(GLOB SOURCES src/*.cpp ${flog_SOURCE_DIR}/lib/flog.cpp)

include_directories(cats-simulator ${CMAKE_CURRENT_BINARY_DIR} ${flog_SOURCE_DIR}/lib)
add_executable(cats-simulator ${SOURCES})
target_link_libraries(cats-simulator CATS)
