#pragma once
#include "jwt/claims.hpp"
#include <vector>

namespace jwt {

/// Account-level claims (middle of trust hierarchy)
class AccountClaims : public Claims {
public:
    /// Create account claims with the given public key
    explicit AccountClaims(const std::string& accountPublicKey);

    // Claims interface
    [[nodiscard]] std::string subject() const override;
    [[nodiscard]] std::string issuer() const override;
    [[nodiscard]] std::optional<std::string> name() const override;
    [[nodiscard]] std::int64_t issuedAt() const override;
    [[nodiscard]] std::int64_t expires() const override;
    [[nodiscard]] std::string encode(const std::string& seed) const override;
    void validate() const override;

    // Account-specific
    void setName(const std::string& name);
    void setExpires(std::int64_t exp);
    void addSigningKey(const std::string& publicKey);
    [[nodiscard]] const std::vector<std::string>& signingKeys() const;

private:
    class Impl;
    std::unique_ptr<Impl> impl_;
};

/// Decode an account JWT
[[nodiscard]] std::unique_ptr<AccountClaims> decodeAccountClaims(const std::string& jwt);

} // namespace jwt
