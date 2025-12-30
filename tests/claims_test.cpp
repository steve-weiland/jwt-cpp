#include <gtest/gtest.h>
#include "jwt/claims.hpp"
#include "jwt/operator_claims.hpp"
#include "jwt/account_claims.hpp"
#include "jwt/user_claims.hpp"

TEST(ClaimsTest, PlaceholderTest) {
    // Placeholder test
    EXPECT_TRUE(true);
}

// TODO: Add real claims tests

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
