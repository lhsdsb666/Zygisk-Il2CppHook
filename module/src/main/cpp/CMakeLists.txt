cmake_minimum_required(VERSION 3.18.1)

if (NOT DEFINED MODULE_NAME)
    message(FATAL_ERROR "MODULE_NAME is not set")
else ()
    project(${MODULE_NAME})
endif ()

message("Build type: ${CMAKE_BUILD_TYPE}")

set(CMAKE_CXX_STANDARD 20)

set(LINKER_FLAGS "-ffixed-x18 -Wl,--hash-style=both")
set(C_FLAGS "-Werror=format -fdata-sections -ffunction-sections")
set(CXX_FLAGS "${CXX_FLAGS} -fno-exceptions -fno-rtti")

if (NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(C_FLAGS "${C_FLAGS} -O2 -fvisibility=hidden -fvisibility-inlines-hidden")
    set(LINKER_FLAGS "${LINKER_FLAGS} -Wl,-exclude-libs,ALL -Wl,--gc-sections -Wl,--strip-all")
else ()
    set(C_FLAGS "${C_FLAGS} -O0")
endif ()

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${C_FLAGS}")
set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} ${C_FLAGS} ${CXX_FLAGS}")

set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${LINKER_FLAGS}")
set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} ${LINKER_FLAGS}")

include_directories(
        xdl/include
)

set(static-lib-location ${CMAKE_CURRENT_SOURCE_DIR}/libs)

add_library(dobby STATIC IMPORTED)
set_target_properties(dobby
        PROPERTIES IMPORTED_LOCATION ${static-lib-location}/${ANDROID_ABI}/libdobby.a)


aux_source_directory(xdl xdl-src)

add_library(${MODULE_NAME} SHARED
        main.cpp
        hack.cpp
        il2cpp_dump.cpp
        ${xdl-src})
target_link_libraries(${MODULE_NAME} dobby log)

if (NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
    add_custom_command(TARGET ${MODULE_NAME} POST_BUILD
            COMMAND ${CMAKE_STRIP} --strip-all --remove-section=.comment "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/lib${MODULE_NAME}.so")
endif ()

# ============================================================
# 免 root 独立注入库 libhack.so —— 打进重打包 APK 的 lib/arm64-v8a/，
# 由 HackProvider（ContentProvider）在 Application 启动前 System.loadLibrary。
# 仅构建 arm64：游戏官方 split 即 arm64-only；x86 模拟器由 NativeBridge
# 自动转译加载（与游戏自带 .so 同理），无需 x86 变体。
# HACK_STANDALONE 宏：排除 hack.cpp 末尾 root/NativeBridge 专用的 JNI_OnLoad，
# 改用 standalone_entry.cpp 提供的入口。
# ============================================================
if (ANDROID_ABI STREQUAL "arm64-v8a")
    add_library(hack SHARED
            standalone_entry.cpp
            hack.cpp
            il2cpp_dump.cpp
            ${xdl-src})
    target_link_libraries(hack dobby log android)
    target_compile_definitions(hack PRIVATE HACK_STANDALONE)

    if (NOT CMAKE_BUILD_TYPE STREQUAL "Debug")
        add_custom_command(TARGET hack POST_BUILD
                COMMAND ${CMAKE_STRIP} --strip-all --remove-section=.comment "${CMAKE_LIBRARY_OUTPUT_DIRECTORY}/libhack.so")
    endif ()
endif ()
