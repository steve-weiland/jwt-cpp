#pragma once

#include <string>
#include <string_view>
#include <vector>
#include <span>
#include <cstdint>

namespace jwt {
namespace internal {

/// Encode bytes to Base64 URL format (RFC 4648, no padding)
/// @param data Input bytes to encode
/// @return Base64 URL encoded string (no padding)
std::string base64url_encode(std::span<const std::uint8_t> data);

/// Decode Base64 URL format to bytes (RFC 4648, padding optional)
/// @param input Base64 URL encoded string
/// @return Decoded bytes
/// @throws std::invalid_argument if input is invalid
std::vector<std::uint8_t> base64url_decode(std::string_view input);

} // namespace internal
} // namespace jwt
