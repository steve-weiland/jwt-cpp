#include "jwt/jwt.hpp"
#include <stdexcept>

namespace jwt {

std::unique_ptr<Claims> decode(const std::string& jwt) {
    // TODO: Implement JWT decoding
    throw std::runtime_error("JWT decoding not yet implemented");
}

bool verify(const std::string& jwt) {
    // TODO: Implement JWT signature verification
    throw std::runtime_error("JWT verification not yet implemented");
}

} // namespace jwt
