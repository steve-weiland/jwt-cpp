add_test([=[ClaimsTest.PlaceholderTest]=]  /Users/steve/src/jwt-cpp/build-auto/claims_test [==[--gtest_filter=ClaimsTest.PlaceholderTest]==] --gtest_also_run_disabled_tests)
set_tests_properties([=[ClaimsTest.PlaceholderTest]=]  PROPERTIES WORKING_DIRECTORY /Users/steve/src/jwt-cpp/build-auto SKIP_REGULAR_EXPRESSION [==[\[  SKIPPED \]]==])
set(  claims_test_TESTS ClaimsTest.PlaceholderTest)
