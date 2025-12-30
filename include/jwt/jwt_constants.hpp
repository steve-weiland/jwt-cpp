#pragma once
#include <cstddef>

namespace jwt {

// JWT version
inline constexpr int JWT_VERSION = 2;

// JWT header algorithm
inline constexpr const char* JWT_ALGORITHM = "ed25519-nkey";

// JWT type
inline constexpr const char* JWT_TYPE = "JWT";

// Maximum JWT size for parsing (10MB)
inline constexpr std::size_t MAX_JWT_SIZE = 10 * 1024 * 1024;

// Claim type prefixes (from nkeys)
// User: 'U', Account: 'A', Operator: 'O'

} // namespace jwt
