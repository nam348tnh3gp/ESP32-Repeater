cmake_minimum_required(VERSION 3.16)

# Đảm bảo IDF tìm thấy thư mục components
set(EXTRA_COMPONENT_DIRS "components")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(APEX_ULTRA)
