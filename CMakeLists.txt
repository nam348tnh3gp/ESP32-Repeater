cmake_minimum_required(VERSION 3.16)

# Ép IDF tìm kiếm trong thư mục components ngay tại project
set(EXTRA_COMPONENT_DIRS "${CMAKE_CURRENT_LIST_DIR}/components")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(APEX_ULTRA)
