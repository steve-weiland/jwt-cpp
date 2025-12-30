#include "jwt/jwt.hpp"
#include "jwt/operator_claims.hpp"
#include "jwt/account_claims.hpp"
#include "jwt/user_claims.hpp"
#include "base64url.hpp"
#include "jwt_utils.hpp"
#include <nlohmann/json.hpp>
#include <stdexcept>

namespace jwt {

std::unique_ptr<Claims> decode(const std::string& jwt) {
    using namespace internal;
    using json = nlohmann::json;

    auto parts = parseJwt(jwt);

    auto payload_bytes = base64url_decode(parts.payload_b64);
    std::string payload_json(payload_bytes.begin(), payload_bytes.end());
    auto payload = json::parse(payload_json);

    if (!payload.contains("nats")) {
        throw std::invalid_argument("Missing 'nats' object in JWT payload");
    }
    auto nats = payload["nats"];

    if (!nats.contains("type")) {
        throw std::invalid_argument("Missing 'type' field in nats object");
    }

    // Dispatch to type-specific decoder
    if (auto type = nats["type"].get<std::string>(); type == "operator") {
        return decodeOperatorClaims(jwt);
    } else if (type == "account") {
        return decodeAccountClaims(jwt);
    } else if (type == "user") {
        return decodeUserClaims(jwt);
    } else {
        throw std::invalid_argument("Unknown JWT type: " + type);
    }
}

bool verify(const std::string& jwt) {
    using namespace internal;
    using json = nlohmann::json;

    try {
        auto parts = parseJwt(jwt);

        auto payload_bytes = base64url_decode(parts.payload_b64);
        std::string payload_json(payload_bytes.begin(), payload_bytes.end());
        auto payload = json::parse(payload_json);

        // Extract issuer (the public key that signed this JWT)
        if (!payload.contains("iss")) {
            return false;
        }
        std::string issuer = payload["iss"].get<std::string>();

        return verifySignature(issuer, parts.signing_input, parts.signature_b64);

    } catch (...) {
        // Any exception means verification failed
        return false;
    }
}

}
