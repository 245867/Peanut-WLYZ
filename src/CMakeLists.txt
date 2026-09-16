# ============================================================
# Peanut WLYZ — CMake 构建配置
# ============================================================
cmake_minimum_required(VERSION 3.16)
project(PeanutWLYZ VERSION 5.0.0 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# ── 编译选项 ───────────────────────────────────────────────
if(MSVC)
    add_compile_options(/utf-8 /W3 /MP)
    add_definitions(-D_CRT_SECURE_NO_WARNINGS -DWIN32_LEAN_AND_MEAN -DNOMINMAX)
    set(CMAKE_MSVC_RUNTIME_LIBRARY "MultiThreaded$<$<CONFIG:Debug>:Debug>")
else()
    add_compile_options(-Wall -Wextra -Wpedantic)
endif()

# ── 查找依赖 ───────────────────────────────────────────────

# ── 客户端核心库 ──────────────────────────────────────────
file(GLOB PEANUT_CLIENT_SOURCES
    src/PeanutClient/protocol/*.cpp
    src/PeanutClient/plugin/*.cpp
    src/PeanutClient/api/*.cpp
    src/PeanutClient/crypto/*.cpp
    src/PeanutClient/util/*.cpp
    src/PeanutClient/transport/*.cpp
)

add_library(peanut_client STATIC ${PEANUT_CLIENT_SOURCES})
target_include_directories(peanut_client PUBLIC
    src/PeanutClient
    src/PeanutClient/protocol
    src/PeanutClient/plugin
    src/PeanutClient/api
    src/PeanutClient/crypto
    src/PeanutClient/util
    src/PeanutClient/transport
)
target_link_libraries(peanut_client PUBLIC
)

# ── TCP transport needs WinSock2 (system DLL, no extra dep) ──
if(WIN32)
    target_link_libraries(peanut_client PUBLIC ws2_32)
endif()

# ── Win32 GUI 可执行文件 ─────────────────────────────────
set(PEANUT_GUI_SOURCES
    src/PeanutGUI/main.cpp
    src/PeanutGUI/main_window.cpp
    src/PeanutGUI/main_window.h
    src/PeanutGUI/win32_controls.h
    src/PeanutGUI/resource.h
    src/PeanutGUI/peanut.rc
)

add_executable(PeanutWLYZ WIN32 ${PEANUT_GUI_SOURCES})

target_include_directories(PeanutWLYZ PRIVATE
    src/PeanutGUI
    src/PeanutClient
    src/PeanutClient/protocol
    src/PeanutClient/plugin
    src/PeanutClient/api
    src/PeanutClient/crypto
    src/PeanutClient/util
    src/PeanutClient/transport
)

target_link_libraries(PeanutWLYZ PRIVATE
    peanut_client
    comctl32
    uxtheme
)

# ── CPP-HTTPlib (header-only, 复制到项目中) ──────────────
# 需要预编译的 httplib.h 可用:
#   - vendor/cpp-httplib/httplib.h (MIT Licence)
#   - 或 git submodule: https://github.com/yhirose/cpp-httplib

# ── NLohmann JSON (header-only) ──────────────────────────
#   - vendor/nlohmann/json.hpp (MIT Licence)
#   - 或 git submodule: https://github.com/nlohmann/json

# ── 安装规则 ─────────────────────────────────────────────
install(TARGETS PeanutWLYZ RUNTIME DESTINATION .)
install(DIRECTORY ${CMAKE_SOURCE_DIR}/plugin/ DESTINATION plugin OPTIONAL)
