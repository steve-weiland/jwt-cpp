#include <gtest/gtest.h>
#include "jwt/jwt.hpp"

TEST(JwtTest, PlaceholderTest) {
    // Placeholder test to ensure test framework works
    EXPECT_TRUE(true);
}

// TODO: Add real JWT encoding/decoding tests

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
