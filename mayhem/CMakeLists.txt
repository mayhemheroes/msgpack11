add_executable(fuzz_pack fuzz_lib.cpp)

target_compile_options(fuzz_pack PRIVATE -fsanitize=fuzzer)
target_link_options(fuzz_pack PRIVATE -fsanitize=fuzzer)

target_link_libraries(fuzz_pack PRIVATE msgpack11)
