#include <gtest/gtest.h>
#include "jwt/jwt.hpp"
#include <nkeys/nkeys.hpp>
#include <nlohmann/json.hpp>
#include "../src/base64url.hpp"

TEST(JwtTest, PlaceholderTest) {
    // Placeholder test to ensure test framework works
    EXPECT_TRUE(true);
}

// Integration test for complete JWT encoding
TEST(JwtEncodingTest, OperatorAccountUserChain) {
    // Create Operator and encode JWT
    auto operator_kp = nkeys::CreateOperator();
    auto op_claims = jwt::OperatorClaims(operator_kp->publicString());
    op_claims.setName("Test Operator");

    std::string operator_jwt = op_claims.encode(operator_kp->seedString());

    // Verify JWT structure (3 parts)
    size_t first_dot = operator_jwt.find('.');
    size_t second_dot = operator_jwt.find('.', first_dot + 1);
    ASSERT_NE(first_dot, std::string::npos);
    ASSERT_NE(second_dot, std::string::npos);
    ASSERT_EQ(operator_jwt.find('.', second_dot + 1), std::string::npos);

    // Decode and verify operator JWT payload
    std::string payload_b64 = operator_jwt.substr(first_dot + 1, second_dot - first_dot - 1);
    auto payload_bytes = jwt::internal::base64url_decode(payload_b64);
    std::string payload_json(payload_bytes.begin(), payload_bytes.end());
    auto payload = nlohmann::json::parse(payload_json);

    EXPECT_EQ(payload["sub"], operator_kp->publicString());
    EXPECT_EQ(payload["iss"], operator_kp->publicString()); // Self-signed
    EXPECT_EQ(payload["name"], "Test Operator");
    EXPECT_TRUE(payload.contains("jti"));
    EXPECT_TRUE(payload.contains("iat"));
    EXPECT_EQ(payload["nats"]["type"], "operator");
    EXPECT_EQ(payload["nats"]["version"], 2);

    // Create Account signed by Operator
    auto account_kp = nkeys::CreateAccount();
    auto acc_claims = jwt::AccountClaims(account_kp->publicString());
    acc_claims.setIssuer(operator_kp->publicString());
    acc_claims.setName("Test Account");

    std::string account_jwt = acc_claims.encode(operator_kp->seedString());

    // Verify account JWT structure
    first_dot = account_jwt.find('.');
    second_dot = account_jwt.find('.', first_dot + 1);
    ASSERT_NE(first_dot, std::string::npos);
    ASSERT_NE(second_dot, std::string::npos);

    payload_b64 = account_jwt.substr(first_dot + 1, second_dot - first_dot - 1);
    payload_bytes = jwt::internal::base64url_decode(payload_b64);
    payload_json = std::string(payload_bytes.begin(), payload_bytes.end());
    payload = nlohmann::json::parse(payload_json);

    EXPECT_EQ(payload["sub"], account_kp->publicString());
    EXPECT_EQ(payload["iss"], operator_kp->publicString()); // Signed by operator
    EXPECT_EQ(payload["nats"]["type"], "account");

    // Create User signed by Account
    auto user_kp = nkeys::CreateUser();
    auto user_claims = jwt::UserClaims(user_kp->publicString());
    user_claims.setIssuer(account_kp->publicString());
    user_claims.setIssuerAccount(account_kp->publicString());
    user_claims.setName("Test User");

    std::string user_jwt = user_claims.encode(account_kp->seedString());

    // Verify user JWT structure
    first_dot = user_jwt.find('.');
    second_dot = user_jwt.find('.', first_dot + 1);
    ASSERT_NE(first_dot, std::string::npos);
    ASSERT_NE(second_dot, std::string::npos);

    payload_b64 = user_jwt.substr(first_dot + 1, second_dot - first_dot - 1);
    payload_bytes = jwt::internal::base64url_decode(payload_b64);
    payload_json = std::string(payload_bytes.begin(), payload_bytes.end());
    payload = nlohmann::json::parse(payload_json);

    EXPECT_EQ(payload["sub"], user_kp->publicString());
    EXPECT_EQ(payload["iss"], account_kp->publicString()); // Signed by account
    EXPECT_EQ(payload["nats"]["type"], "user");
    EXPECT_EQ(payload["nats"]["issuer_account"], account_kp->publicString());

    // All JWTs should be non-empty
    EXPECT_FALSE(operator_jwt.empty());
    EXPECT_FALSE(account_jwt.empty());
    EXPECT_FALSE(user_jwt.empty());
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
