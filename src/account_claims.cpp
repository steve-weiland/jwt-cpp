#include "jwt/account_claims.hpp"
#include "jwt/jwt_constants.hpp"
#include "base64url.hpp"
#include "jwt_utils.hpp"
#include <nlohmann/json.hpp>
#include <stdexcept>

namespace jwt {

// Pimpl implementation placeholder
class AccountClaims::Impl {
public:
    std::string subject_;
    std::string issuer_;
    std::optional<std::string> name_;
    std::int64_t issuedAt_ = 0;
    std::int64_t expires_ = 0;
    std::vector<std::string> signingKeys_;
};

AccountClaims::AccountClaims(const std::string& accountPublicKey)
    : impl_(std::make_unique<Impl>()) {
    impl_->subject_ = accountPublicKey;
}

AccountClaims::~AccountClaims() = default;

std::string AccountClaims::subject() const { return impl_->subject_; }
std::string AccountClaims::issuer() const { return impl_->issuer_; }
std::optional<std::string> AccountClaims::name() const { return impl_->name_; }
std::int64_t AccountClaims::issuedAt() const { return impl_->issuedAt_; }
std::int64_t AccountClaims::expires() const { return impl_->expires_; }

void AccountClaims::setName(const std::string& name) { impl_->name_ = name; }
void AccountClaims::setExpires(std::int64_t exp) { impl_->expires_ = exp; }
void AccountClaims::setIssuer(const std::string& issuerKey) { impl_->issuer_ = issuerKey; }
void AccountClaims::addSigningKey(const std::string& publicKey) {
    impl_->signingKeys_.push_back(publicKey);
}
const std::vector<std::string>& AccountClaims::signingKeys() const {
    return impl_->signingKeys_;
}

std::string AccountClaims::encode(const std::string& seed) const {
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
        {"type", "account"},
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

void AccountClaims::validate() const {
    if (impl_->subject_.empty()) {
        throw std::invalid_argument("Account subject cannot be empty");
    }
    if (impl_->issuer_.empty()) {
        throw std::invalid_argument("Account issuer cannot be empty (must be signed by Operator)");
    }
    if (impl_->subject_[0] != 'A') {
        throw std::invalid_argument("Account subject must start with 'A'");
    }
    if (impl_->issuer_[0] != 'O') {
        throw std::invalid_argument("Account issuer must be an Operator (start with 'O')");
    }
    if (impl_->expires_ > 0 && impl_->issuedAt_ > 0 &&
        impl_->expires_ <= impl_->issuedAt_) {
        throw std::invalid_argument("Expiration must be after issuedAt");
    }
}

std::unique_ptr<AccountClaims> decodeAccountClaims(const std::string& jwt) {
    // TODO: Implement decoding
    throw std::runtime_error("Account JWT decoding not yet implemented");
}

} // namespace jwt
