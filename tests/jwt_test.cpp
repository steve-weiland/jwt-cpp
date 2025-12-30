#include <gtest/gtest.h>
#include "jwt/jwt.hpp"
#include <nkeys/nkeys.hpp>
#include <nlohmann/json.hpp>
#include "../src/base64url.hpp"
#include <fstream>
#include <sstream>
#include <cstdio>

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

// Round-trip test: Operator encode → decode
TEST(JwtDecodingTest, OperatorRoundTrip) {
    auto operator_kp = nkeys::CreateOperator();

    // Create and encode operator claims
    auto original = jwt::OperatorClaims(operator_kp->publicString());
    original.setName("Test Operator");
    original.addSigningKey("OABC123");

    std::string jwt_string = original.encode(operator_kp->seedString());

    // Decode the JWT
    auto decoded = jwt::decodeOperatorClaims(jwt_string);

    // Verify all fields match
    EXPECT_EQ(decoded->subject(), original.subject());
    EXPECT_EQ(decoded->issuer(), original.issuer());
    EXPECT_EQ(decoded->name(), original.name());
    EXPECT_GT(decoded->issuedAt(), 0);
    EXPECT_EQ(decoded->expires(), 0); // Not set
    EXPECT_EQ(decoded->signingKeys().size(), 1);
    EXPECT_EQ(decoded->signingKeys()[0], "OABC123");
}

// Round-trip test: Account encode → decode
TEST(JwtDecodingTest, AccountRoundTrip) {
    auto operator_kp = nkeys::CreateOperator();
    auto account_kp = nkeys::CreateAccount();

    // Create and encode account claims
    auto original = jwt::AccountClaims(account_kp->publicString());
    original.setIssuer(operator_kp->publicString());
    original.setName("Test Account");
    original.setExpires(9999999999);
    original.addSigningKey("AABC123");
    original.addSigningKey("AXYZ789");

    std::string jwt_string = original.encode(operator_kp->seedString());

    // Decode the JWT
    auto decoded = jwt::decodeAccountClaims(jwt_string);

    // Verify all fields match
    EXPECT_EQ(decoded->subject(), original.subject());
    EXPECT_EQ(decoded->issuer(), original.issuer());
    EXPECT_EQ(decoded->name(), original.name());
    EXPECT_GT(decoded->issuedAt(), 0);
    EXPECT_EQ(decoded->expires(), 9999999999);
    EXPECT_EQ(decoded->signingKeys().size(), 2);
    EXPECT_EQ(decoded->signingKeys()[0], "AABC123");
    EXPECT_EQ(decoded->signingKeys()[1], "AXYZ789");
}

// Round-trip test: User encode → decode
TEST(JwtDecodingTest, UserRoundTrip) {
    auto account_kp = nkeys::CreateAccount();
    auto user_kp = nkeys::CreateUser();

    // Create and encode user claims
    auto original = jwt::UserClaims(user_kp->publicString());
    original.setIssuer(account_kp->publicString());
    original.setIssuerAccount(account_kp->publicString());
    original.setName("Test User");
    original.setExpires(8888888888);

    std::string jwt_string = original.encode(account_kp->seedString());

    // Decode the JWT
    auto decoded = jwt::decodeUserClaims(jwt_string);

    // Verify all fields match
    EXPECT_EQ(decoded->subject(), original.subject());
    EXPECT_EQ(decoded->issuer(), original.issuer());
    EXPECT_EQ(decoded->name(), original.name());
    EXPECT_EQ(decoded->issuerAccount(), original.issuerAccount());
    EXPECT_GT(decoded->issuedAt(), 0);
    EXPECT_EQ(decoded->expires(), 8888888888);
}

// Test generic decode with all three types
TEST(JwtDecodingTest, GenericDecodeAllTypes) {
    // Operator JWT
    auto operator_kp = nkeys::CreateOperator();
    auto op_claims = jwt::OperatorClaims(operator_kp->publicString());
    op_claims.setName("Generic Operator");
    std::string op_jwt = op_claims.encode(operator_kp->seedString());

    auto decoded_op = jwt::decode(op_jwt);
    EXPECT_EQ(decoded_op->subject(), operator_kp->publicString());
    EXPECT_EQ(decoded_op->name().value(), "Generic Operator");

    // Account JWT
    auto account_kp = nkeys::CreateAccount();
    auto acc_claims = jwt::AccountClaims(account_kp->publicString());
    acc_claims.setIssuer(operator_kp->publicString());
    acc_claims.setName("Generic Account");
    std::string acc_jwt = acc_claims.encode(operator_kp->seedString());

    auto decoded_acc = jwt::decode(acc_jwt);
    EXPECT_EQ(decoded_acc->subject(), account_kp->publicString());
    EXPECT_EQ(decoded_acc->issuer(), operator_kp->publicString());

    // User JWT
    auto user_kp = nkeys::CreateUser();
    auto user_claims = jwt::UserClaims(user_kp->publicString());
    user_claims.setIssuer(account_kp->publicString());
    user_claims.setName("Generic User");
    std::string user_jwt = user_claims.encode(account_kp->seedString());

    auto decoded_user = jwt::decode(user_jwt);
    EXPECT_EQ(decoded_user->subject(), user_kp->publicString());
    EXPECT_EQ(decoded_user->issuer(), account_kp->publicString());
}

// Test signature verification - valid signature
TEST(JwtVerificationTest, ValidSignature) {
    auto operator_kp = nkeys::CreateOperator();
    auto op_claims = jwt::OperatorClaims(operator_kp->publicString());
    std::string jwt_string = op_claims.encode(operator_kp->seedString());

    // Verify with correct signature
    EXPECT_TRUE(jwt::verify(jwt_string));
}

// Test signature verification - corrupted JWT
TEST(JwtVerificationTest, CorruptedJwt) {
    auto operator_kp = nkeys::CreateOperator();
    auto op_claims = jwt::OperatorClaims(operator_kp->publicString());
    std::string jwt_string = op_claims.encode(operator_kp->seedString());

    // Find signature part (after second dot)
    size_t second_dot = jwt_string.rfind('.');

    // Corrupt the signature in the middle where all 6 bits matter
    // (not the last character which may have padding bits)
    size_t middle_of_sig = second_dot + 1 + 43;  // Middle of 86-char signature
    char original_char = jwt_string[middle_of_sig];

    // Change to a different character (A→B ensures all bits change)
    jwt_string[middle_of_sig] = (original_char == 'A') ? 'B' : 'A';

    // Verification should fail
    EXPECT_FALSE(jwt::verify(jwt_string));
}

// Test signature verification - wrong issuer
TEST(JwtVerificationTest, WrongIssuer) {
    auto operator_kp = nkeys::CreateOperator();
    auto wrong_operator_kp = nkeys::CreateOperator();

    auto op_claims = jwt::OperatorClaims(operator_kp->publicString());

    // Sign with wrong key
    std::string jwt_string = op_claims.encode(wrong_operator_kp->seedString());

    // Verification should fail (issuer in payload doesn't match signing key)
    EXPECT_FALSE(jwt::verify(jwt_string));
}

// Test malformed JWT - missing parts
TEST(JwtDecodingTest, MalformedJwtMissingParts) {
    EXPECT_THROW(jwt::decode("header.payload"), std::invalid_argument);
    EXPECT_THROW(jwt::decode("onlyonepart"), std::invalid_argument);
    EXPECT_THROW(jwt::decode(""), std::invalid_argument);
}

// Test malformed JWT - too many parts
TEST(JwtDecodingTest, MalformedJwtTooManyParts) {
    EXPECT_THROW(jwt::decode("a.b.c.d"), std::invalid_argument);
}

// Test malformed JWT - empty parts
TEST(JwtDecodingTest, MalformedJwtEmptyParts) {
    EXPECT_THROW(jwt::decode(".payload.signature"), std::invalid_argument);
    EXPECT_THROW(jwt::decode("header..signature"), std::invalid_argument);
    EXPECT_THROW(jwt::decode("header.payload."), std::invalid_argument);
}

// Test invalid Base64
TEST(JwtDecodingTest, InvalidBase64) {
    EXPECT_THROW(jwt::decode("!!!.@@@.###"), std::exception);
}

// Test type mismatch - decode account as operator
TEST(JwtDecodingTest, TypeMismatchAccountAsOperator) {
    auto operator_kp = nkeys::CreateOperator();
    auto account_kp = nkeys::CreateAccount();

    auto acc_claims = jwt::AccountClaims(account_kp->publicString());
    acc_claims.setIssuer(operator_kp->publicString());
    std::string acc_jwt = acc_claims.encode(operator_kp->seedString());

    // Try to decode as operator - should throw
    EXPECT_THROW(jwt::decodeOperatorClaims(acc_jwt), std::invalid_argument);
}

// Test type mismatch - decode user as account
TEST(JwtDecodingTest, TypeMismatchUserAsAccount) {
    auto account_kp = nkeys::CreateAccount();
    auto user_kp = nkeys::CreateUser();

    auto user_claims = jwt::UserClaims(user_kp->publicString());
    user_claims.setIssuer(account_kp->publicString());
    std::string user_jwt = user_claims.encode(account_kp->seedString());

    // Try to decode as account - should throw
    EXPECT_THROW(jwt::decodeAccountClaims(user_jwt), std::invalid_argument);
}

// Test minimal JWT (no optional fields)
TEST(JwtDecodingTest, MinimalJwt) {
    auto operator_kp = nkeys::CreateOperator();

    // Create operator with only required fields
    auto op_claims = jwt::OperatorClaims(operator_kp->publicString());
    // Don't set name, expires, or signing keys

    std::string jwt_string = op_claims.encode(operator_kp->seedString());
    auto decoded = jwt::decodeOperatorClaims(jwt_string);

    EXPECT_EQ(decoded->subject(), operator_kp->publicString());
    EXPECT_FALSE(decoded->name().has_value());
    EXPECT_EQ(decoded->expires(), 0);
    EXPECT_TRUE(decoded->signingKeys().empty());
}

// ============================================================================
// formatUserConfig Tests (Creds File Generation)
// ============================================================================

TEST(FormatUserConfigTest, GeneratesValidCredsFile) {
    auto account_kp = nkeys::CreateAccount();
    auto user_kp = nkeys::CreateUser();

    // Create and encode user JWT
    jwt::UserClaims claims(user_kp->publicString());
    claims.setIssuer(account_kp->publicString());
    claims.setName("Test User");

    std::string jwt_string = claims.encode(account_kp->seedString());
    std::string seed = user_kp->seedString();

    // Format creds file
    std::string creds = jwt::formatUserConfig(jwt_string, seed);

    // Verify format structure
    EXPECT_NE(creds.find("-----BEGIN NATS USER JWT-----"), std::string::npos);
    EXPECT_NE(creds.find("------END NATS USER JWT------"), std::string::npos);
    EXPECT_NE(creds.find("-----BEGIN USER NKEY SEED-----"), std::string::npos);
    EXPECT_NE(creds.find("------END USER NKEY SEED------"), std::string::npos);
    EXPECT_NE(creds.find("IMPORTANT"), std::string::npos);
    EXPECT_NE(creds.find("NKEYs are sensitive"), std::string::npos);

    // Verify JWT is present in the creds file
    EXPECT_NE(creds.find(jwt_string.substr(0, 20)), std::string::npos);

    // Verify seed is present
    EXPECT_NE(creds.find(seed), std::string::npos);
}

TEST(FormatUserConfigTest, JwtIsWrappedAt64Chars) {
    auto account_kp = nkeys::CreateAccount();
    auto user_kp = nkeys::CreateUser();

    jwt::UserClaims claims(user_kp->publicString());
    claims.setIssuer(account_kp->publicString());

    std::string jwt_string = claims.encode(account_kp->seedString());
    std::string creds = jwt::formatUserConfig(jwt_string, user_kp->seedString());

    // Find the JWT section
    size_t jwt_start = creds.find("-----BEGIN NATS USER JWT-----") + 30;
    size_t jwt_end = creds.find("------END NATS USER JWT------");

    std::string jwt_section = creds.substr(jwt_start, jwt_end - jwt_start);

    // Split into lines and check each line is <= 64 chars (plus newline)
    std::istringstream iss(jwt_section);
    std::string line;
    while (std::getline(iss, line)) {
        if (!line.empty()) {
            EXPECT_LE(line.length(), 64) << "Line too long: " << line;
        }
    }
}

TEST(FormatUserConfigTest, RejectsEmptyJwt) {
    auto user_kp = nkeys::CreateUser();
    EXPECT_THROW(
        jwt::formatUserConfig("", user_kp->seedString()),
        std::invalid_argument
    );
}

TEST(FormatUserConfigTest, RejectsEmptySeed) {
    auto account_kp = nkeys::CreateAccount();
    auto user_kp = nkeys::CreateUser();

    jwt::UserClaims claims(user_kp->publicString());
    claims.setIssuer(account_kp->publicString());
    std::string jwt_string = claims.encode(account_kp->seedString());

    EXPECT_THROW(
        jwt::formatUserConfig(jwt_string, ""),
        std::invalid_argument
    );
}

TEST(FormatUserConfigTest, RejectsNonUserSeed) {
    auto account_kp = nkeys::CreateAccount();
    auto user_kp = nkeys::CreateUser();

    jwt::UserClaims claims(user_kp->publicString());
    claims.setIssuer(account_kp->publicString());
    std::string jwt_string = claims.encode(account_kp->seedString());

    // Try to use account seed instead of user seed
    EXPECT_THROW(
        jwt::formatUserConfig(jwt_string, account_kp->seedString()),
        std::invalid_argument
    );
}

TEST(FormatUserConfigTest, HandlesShortJwt) {
    auto user_kp = nkeys::CreateUser();

    // Create a short fake JWT (less than 64 chars)
    std::string short_jwt = "header.payload.sig";

    std::string creds = jwt::formatUserConfig(short_jwt, user_kp->seedString());

    // Verify it still has proper structure
    EXPECT_NE(creds.find("-----BEGIN NATS USER JWT-----"), std::string::npos);
    EXPECT_NE(creds.find(short_jwt), std::string::npos);
}

TEST(FormatUserConfigTest, CredsFileCanBeWrittenToFile) {
    auto account_kp = nkeys::CreateAccount();
    auto user_kp = nkeys::CreateUser();

    jwt::UserClaims claims(user_kp->publicString());
    claims.setIssuer(account_kp->publicString());
    claims.setName("Test User");

    std::string jwt_string = claims.encode(account_kp->seedString());
    std::string creds = jwt::formatUserConfig(jwt_string, user_kp->seedString());

    // Write to temporary file
    std::string temp_file = "/tmp/test_user.creds";
    std::ofstream ofs(temp_file);
    ASSERT_TRUE(ofs.is_open());
    ofs << creds;
    ofs.close();

    // Read it back
    std::ifstream ifs(temp_file);
    ASSERT_TRUE(ifs.is_open());
    std::string read_creds((std::istreambuf_iterator<char>(ifs)),
                           std::istreambuf_iterator<char>());
    ifs.close();

    // Verify content matches
    EXPECT_EQ(read_creds, creds);

    // Clean up
    std::remove(temp_file.c_str());
}

int main(int argc, char **argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}
