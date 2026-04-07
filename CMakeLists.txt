cmake_minimum_required(VERSION 3.16)

# Dòng này giúp IDF quét toàn bộ thư mục components bạn vừa clone về
set(EXTRA_COMPONENT_DIRS "components")

include($ENV{IDF_PATH}/tools/cmake/project.cmake)
project(APEX_ULTRA)
