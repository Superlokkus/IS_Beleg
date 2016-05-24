cmake_minimum_required(VERSION 3.4)
project(IS_Beleg)

set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_SOURCE_DIR}/modules/")

find_package(OpenSSL REQUIRED)
include_directories(OPENSSL_INCLUDE_DIR)

set(LIBS ${OPENSSL_LIBRARIES})

set(SOURCE_FILES s70357.c)
add_executable(is_beleg ${SOURCE_FILES})

TARGET_LINK_LIBRARIES(is_beleg ${LIBS})

set_property(TARGET is_beleg PROPERTY LINKER_LANGUAGE C)
set_property(TARGET is_beleg PROPERTY C_STANDARD 11)
set_property(TARGET is_beleg PROPERTY C_STANDARD_REQUIRED TRUE)