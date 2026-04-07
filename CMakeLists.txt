cmake_minimum_required(VERSION 3.16)

# Ép IDF tìm kiếm thư viện trong thư mục components (CI sẽ tự tạo thư mục này)
set(EXTRA_COMPONENT_DIRS "components")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(APEX_ULTRA)
