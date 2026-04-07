# main/CMakeLists.txt
idf_component_register(SRCS "../ESP_Code.ino"
                    INCLUDE_DIRS "."
                    PRIV_REQUIRES arduino-esp32)

set_source_files_properties("../ESP_Code.ino" PROPERTIES LANGUAGE CXX)
