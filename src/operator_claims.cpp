#include "jwt/operator_claims.hpp"
#include "jwt/jwt_constants.hpp"
#include "base64url.hpp"
#include "jwt_utils.hpp"
#include <nlohmann/json.hpp>
#include <stdexcept>

namespace jwt {

// Pimpl implementation placeholder
class OperatorClaims::Impl {
public:
    std::string subject_;
    std::string issuer_;
    std::optional<std::string> name_;
    std::int64_t issuedAt_ = 0;
    std::int64_t expires_ = 0;
    std::vector<std::string> signingKeys_;
};

OperatorClaims::OperatorClaims(const std::string& operatorPublicKey)
    : impl_(std::make_unique<Impl>()) {
    impl_->subject_ = operatorPublicKey;
    impl_->issuer_ = operatorPublicKey;  // Self-signed
}

OperatorClaims::~OperatorClaims() = default;

std::string OperatorClaims::subject() const { return impl_->subject_; }
std::string OperatorClaims::issuer() const { return impl_->issuer_; }
std::optional<std::string> OperatorClaims::name() const { return impl_->name_; }
std::int64_t OperatorClaims::issuedAt() const { return impl_->issuedAt_; }
std::int64_t OperatorClaims::expires() const { return impl_->expires_; }

void OperatorClaims::setName(const std::string& name) { impl_->name_ = name; }
void OperatorClaims::setExpires(std::int64_t exp) { impl_->expires_ = exp; }
void OperatorClaims::addSigningKey(const std::string& publicKey) {
    impl_->signingKeys_.push_back(publicKey);
}
const std::vector<std::string>& OperatorClaims::signingKeys() const {
    return impl_->signingKeys_;
}

std::string OperatorClaims::encode(const std::string& seed) const {
    using namespace internal;
    using json = nlohmann::json;

    validate();

    // Auto-generate JTI and issuedAt
    std::string jti = generateJti();
    std::int64_t iat = (impl_->issuedAt_ == 0) ? getCurrentTimestamp() : impl_->issuedAt_;

    // Build payload JSON
    json payload = {
        {"jti", jti},
        {"iat", iat},
        {"iss", impl_->issuer_},
        {"sub", impl_->subject_}
    };

    if (impl_->name_) {
        payload["name"] = *impl_->name_;
    }
    if (impl_->expires_ > 0) {
        payload["exp"] = impl_->expires_;
    }

    // NATS-specific claims
    json nats_claims = {
        {"type", "operator"},
        {"version", JWT_VERSION}
    };
    if (!impl_->signingKeys_.empty()) {
        nats_claims["signing_keys"] = impl_->signingKeys_;
    }
    payload["nats"] = nats_claims;

    // Create JWT: header.payload.signature
    std::string header_json = createHeader();
    std::string payload_json = payload.dump();

    // Convert strings to byte spans for encoding
    std::span<const std::uint8_t> header_bytes(
        reinterpret_cast<const std::uint8_t*>(header_json.data()),
        header_json.size()
    );
    std::span<const std::uint8_t> payload_bytes(
        reinterpret_cast<const std::uint8_t*>(payload_json.data()),
        payload_json.size()
    );

    std::string header_b64 = base64url_encode(header_bytes);
    std::string payload_b64 = base64url_encode(payload_bytes);

    // Sign "header.payload"
    std::string signing_input = header_b64 + "." + payload_b64;
    std::span<const std::uint8_t> signing_bytes(
        reinterpret_cast<const std::uint8_t*>(signing_input.data()),
        signing_input.size()
    );

    auto signature_bytes = signData(seed, signing_bytes);
    std::string signature_b64 = base64url_encode(signature_bytes);

    return signing_input + "." + signature_b64;
}

void OperatorClaims::validate() const {
    if (impl_->subject_.empty()) {
        throw std::invalid_argument("Operator subject cannot be empty");
    }
    if (impl_->issuer_.empty()) {
        throw std::invalid_argument("Operator issuer cannot be empty");
    }
    if (impl_->subject_[0] != 'O') {
        throw std::invalid_argument("Operator subject must start with 'O'");
    }
    if (impl_->expires_ > 0 && impl_->issuedAt_ > 0 &&
        impl_->expires_ <= impl_->issuedAt_) {
        throw std::invalid_argument("Expiration must be after issuedAt");
    }
}

std::unique_ptr<OperatorClaims> decodeOperatorClaims(const std::string& jwt) {
    // TODO: Implement decoding
    throw std::runtime_error("Operator JWT decoding not yet implemented");
}

} // namespace jwt
