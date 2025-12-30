#include "jwt/user_claims.hpp"
#include <stdexcept>

namespace jwt {

// Pimpl implementation placeholder
class UserClaims::Impl {
public:
    std::string subject_;
    std::string issuer_;
    std::optional<std::string> name_;
    std::int64_t issuedAt_ = 0;
    std::int64_t expires_ = 0;
    std::optional<std::string> issuerAccount_;
};

UserClaims::UserClaims(const std::string& userPublicKey)
    : impl_(std::make_unique<Impl>()) {
    impl_->subject_ = userPublicKey;
}

std::string UserClaims::subject() const { return impl_->subject_; }
std::string UserClaims::issuer() const { return impl_->issuer_; }
std::optional<std::string> UserClaims::name() const { return impl_->name_; }
std::int64_t UserClaims::issuedAt() const { return impl_->issuedAt_; }
std::int64_t UserClaims::expires() const { return impl_->expires_; }

void UserClaims::setName(const std::string& name) { impl_->name_ = name; }
void UserClaims::setExpires(std::int64_t exp) { impl_->expires_ = exp; }
void UserClaims::setIssuerAccount(const std::string& accountPublicKey) {
    impl_->issuerAccount_ = accountPublicKey;
}
std::optional<std::string> UserClaims::issuerAccount() const {
    return impl_->issuerAccount_;
}

std::string UserClaims::encode(const std::string& seed) const {
    // TODO: Implement encoding
    throw std::runtime_error("User JWT encoding not yet implemented");
}

void UserClaims::validate() const {
    // TODO: Implement validation
}

std::unique_ptr<UserClaims> decodeUserClaims(const std::string& jwt) {
    // TODO: Implement decoding
    throw std::runtime_error("User JWT decoding not yet implemented");
}

std::string formatUserConfig(const std::string& jwt, const std::string& seed) {
    // TODO: Implement creds file formatting
    throw std::runtime_error("Creds file formatting not yet implemented");
}

} // namespace jwt
