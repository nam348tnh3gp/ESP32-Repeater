cmake_minimum_required(VERSION 3.16)

# Cho phép tìm các thư viện trong thư mục components
set(EXTRA_COMPONENT_DIRS "components")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)

# Tên project phải khớp với lệnh mv trong file .yml
project(APEX_ULTRA)
