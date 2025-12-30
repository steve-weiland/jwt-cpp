#pragma once

#include <string>
#include <cstdint>
#include <vector>
#include <span>

namespace jwt {
namespace internal {

/// Generate a random JWT ID (32 hex chars from 16 random bytes)
/// @return 32-character hex string
std::string generateJti();

/// Get current Unix timestamp in seconds
/// @return Unix timestamp (seconds since epoch)
std::int64_t getCurrentTimestamp();

/// Create JWT header as JSON string
/// @return JSON string: {"typ":"JWT","alg":"ed25519-nkey"}
std::string createHeader();

/// Sign data with Ed25519 key and return signature bytes
/// @param seed Ed25519 seed string (e.g., "SOABC...")
/// @param data Data to sign
/// @return 64-byte Ed25519 signature
std::vector<std::uint8_t> signData(const std::string& seed,
                                     std::span<const std::uint8_t> data);

} // namespace internal
} // namespace jwt
