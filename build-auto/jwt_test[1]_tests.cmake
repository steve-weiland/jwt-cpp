add_test([=[JwtTest.PlaceholderTest]=]  /Users/steve/src/jwt-cpp/build-auto/jwt_test [==[--gtest_filter=JwtTest.PlaceholderTest]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[JwtTest.PlaceholderTest]=]  PROPERTIES WORKING_DIRECTORY /Users/steve/src/jwt-cpp/build-auto SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==])
set(  jwt_test_TESTS JwtTest.PlaceholderTest)
