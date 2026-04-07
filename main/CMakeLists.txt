# main/CMakeLists.txt
set(SOURCES "../ESP_Code.ino")

idf_component_register(SRCS ${SOURCES}
                    INCLUDE_DIRS "."
                    PRIV_REQUIRES arduino-esp32)

# Ép kiểu C++ cho file .ino
set_source_files_properties("../ESP_Code.ino" PROPERTIES LANGUAGE CXX)
