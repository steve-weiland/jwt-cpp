#include "jwt_utils.hpp"
#include "jwt/jwt_constants.hpp"
#include <nkeys/nkeys.hpp>
#include <nlohmann/json.hpp>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <array>

namespace jwt {
namespace internal {

std::string generateJti() {
    std::array<std::uint8_t, 16> random_bytes;
    nkeys::secureRandomBytes(random_bytes);

    std::ostringstream oss;
    oss << std::hex << std::setfill('0');
    for (auto byte : random_bytes) {
        oss << std::setw(2) << static_cast<unsigned int>(byte);
    }
    return oss.str();
}

std::int64_t getCurrentTimestamp() {
    using namespace std::chrono;
    return duration_cast<seconds>(system_clock::now().time_since_epoch()).count();
}

std::string createHeader() {
    nlohmann::json header;
    header["typ"] = JWT_TYPE;
    header["alg"] = JWT_ALGORITHM;
    return header.dump();
}

std::vector<std::uint8_t> signData(const std::string& seed,
                                     std::span<const std::uint8_t> data) {
    auto keypair = nkeys::FromSeed(seed);
    return keypair->sign(data);
}

} // namespace internal
} // namespace jwt
