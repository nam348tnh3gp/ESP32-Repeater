cmake_minimum_required(VERSION 3.16)

# Cho phép IDF tìm thấy các thư viện trong thư mục components
set(EXTRA_COMPONENT_DIRS "components")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

# Tên dự án (dùng để xác định tên file .bin đầu ra)
project(APEX_ULTRA)
