
aux_source_directory(. SRC)
add_executable(webench++ ${SRC})
target_link_libraries(webench++ pthread)