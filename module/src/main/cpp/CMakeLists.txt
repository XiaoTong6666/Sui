cmake_minimum_required(VERSION 3.31)

project("sui")

message("Build type: ${CMAKE_BUILD_TYPE} Zygisk")

set(CMAKE_CXX_STANDARD 17)

add_link_options(-ffixed-x18 -Wl,--hash-style=both -static-libstdc++)
add_compile_options(-Werror=format -fdata-sections -ffunction-sections -fno-exceptions -fno-rtti -fno-threadsafe-statics -U_FORTIFY_SOURCE -D_FORTIFY_SOURCE=0)

if (NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_definitions(-DNDEBUG)
    add_compile_options(-O3 -flto -fvisibility-inlines-hidden)
    add_link_options(-flto -Wl,--exclude-libs,ALL -Wl,--gc-sections -Wl,--strip-all)
else ()
    add_definitions(-DDEBUG)
    add_compile_options(-O0)
endif ()

find_package(cxx REQUIRED CONFIG)
find_package(nativehelper REQUIRED CONFIG)

include_directories(".")
include_directories("include")
include_directories("util/include")

add_library(util STATIC
        util/misc.cpp
        util/dex_file.cpp
        util/android.cpp
        util/plt.c
        util/selinux.cpp
        util/memory.cpp
        util/app_process.cpp
        util/socket.cpp)
target_link_libraries(util cxx::cxx log nativehelper::nativehelper_header_only)

add_definitions(-DZYGISK_MODULE_ID=${ZYGISK_MODULE_ID})

add_library(sui SHARED
        core/main_zygisk.cpp
        core/main.cpp
        core/system_server.cpp
        core/binder_hook.cpp
        core/bridge_service.cpp
        core/manager_process.cpp
        core/settings_process.cpp)
target_link_libraries(sui util cxx::cxx log nativehelper::nativehelper_header_only)
set_target_properties(sui PROPERTIES LINK_FLAGS_RELEASE -s)

add_executable(libmain.so main/main.cpp)
target_link_libraries(libmain.so util cxx::cxx log nativehelper::nativehelper_header_only)
set_target_properties(libmain.so PROPERTIES LINK_FLAGS_RELEASE -s)

add_executable(libadbd_wrapper.so
        adbd/adbd_wrapper_main.cpp)
target_link_libraries(libadbd_wrapper.so cxx::cxx log)
set_target_properties(libadbd_wrapper.so PROPERTIES LINK_FLAGS_RELEASE -s)

add_library(adbd_preload SHARED
        adbd/adbd_preload.cpp)
target_link_libraries(adbd_preload cxx::cxx log)
set_target_properties(adbd_preload PROPERTIES LINK_FLAGS_RELEASE -s)

add_executable(libsepolicy_checker.so checker/checker_main.cpp)
target_link_libraries(libsepolicy_checker.so util cxx::cxx log nativehelper::nativehelper_header_only)
set_target_properties(libsepolicy_checker.so PROPERTIES LINK_FLAGS_RELEASE -s)

if (NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_custom_command(TARGET sui POST_BUILD
            COMMAND ${CMAKE_STRIP} --strip-all --remove-section=.comment "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libsui.so")

    add_custom_command(TARGET libmain.so POST_BUILD
            COMMAND ${CMAKE_STRIP} --strip-all --remove-section=.comment "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libmain.so")

    add_custom_command(TARGET libadbd_wrapper.so POST_BUILD
            COMMAND ${CMAKE_STRIP} --strip-all --remove-section=.comment "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libadbd_wrapper.so")

    add_custom_command(TARGET adbd_preload POST_BUILD
            COMMAND ${CMAKE_STRIP} --strip-all --remove-section=.comment "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libadbd_preload.so")

    add_custom_command(TARGET libsepolicy_checker.so POST_BUILD
            COMMAND ${CMAKE_STRIP} --strip-all --remove-section=.comment "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libsepolicy_checker.so")
endif ()
