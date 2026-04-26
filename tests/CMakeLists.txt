add_executable(test_util test_util.cpp ../src/util.cpp)
target_include_directories(test_util PRIVATE ../src)
add_test(NAME test_util COMMAND test_util)
