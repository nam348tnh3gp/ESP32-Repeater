# Đăng ký file .ino từ thư mục cha vào quá trình build
idf_component_register(SRCS "../ESP_Code.ino"
                    INCLUDE_DIRS "."
                    PRIV_REQUIRES arduino-esp32)

# Ép kiểu C++ để tránh lỗi biên dịch
set_source_files_properties("../ESP_Code.ino" PROPERTIES LANGUAGE CXX)
