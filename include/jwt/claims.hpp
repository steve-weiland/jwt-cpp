#pragma once
#include <string>
#include <memory>
#include <cstdint>
#include <optional>

namespace jwt {

/// Base class for all JWT claims
class Claims {
public:
    virtual ~Claims() = default;

    /// Get the subject (public key of the claim holder)
    [[nodiscard]] virtual std::string subject() const = 0;

    /// Get the issuer (public key of the signer)
    [[nodiscard]] virtual std::string issuer() const = 0;

    /// Get the claim name
    [[nodiscard]] virtual std::optional<std::string> name() const = 0;

    /// Get the issued-at timestamp (Unix seconds)
    [[nodiscard]] virtual std::int64_t issuedAt() const = 0;

    /// Get the expiration timestamp (Unix seconds, 0 = no expiration)
    [[nodiscard]] virtual std::int64_t expires() const = 0;

    /// Encode the claims to a JWT string signed with the given keypair
    [[nodiscard]] virtual std::string encode(const std::string& seed) const = 0;

    /// Validate the claims structure
    virtual void validate() const = 0;
};

/// Decode a JWT string into claims
[[nodiscard]] std::unique_ptr<Claims> decode(const std::string& jwt);

/// Verify a JWT signature
[[nodiscard]] bool verify(const std::string& jwt);

} // namespace jwt
