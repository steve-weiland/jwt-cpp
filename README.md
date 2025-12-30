# jwt-cpp

A C++20 implementation of the NATS JWT library for Ed25519-based authentication tokens.

## Overview

This library provides JWT (JSON Web Token) encoding and decoding specifically designed for NATS authentication. It uses Ed25519 digital signatures via the nkeys-cpp library.

**Status:** 🚧 Bootstrap phase complete - Core implementation in progress

### Features (Planned)

- **Operator/Account/User Claims**: Three-tier authorization hierarchy
- **Ed25519 Signatures**: Secure digital signatures using nkeys-cpp
- **JSON Encoding**: JWT encoding/decoding with nlohmann/json
- **Creds File Format**: NATS credentials file generation
- **Modern C++20**: Type-safe API with `std::unique_ptr`, `std::optional`, and exceptions

## Quick Start

### Prerequisites

- C++20 compatible compiler (GCC 10+, Clang 12+, MSVC 19.29+)
- CMake 3.20 or higher
- Git (for automatic dependency fetching)

### Building

jwt-cpp automatically downloads and builds nkeys-cpp if it's not found on your system.

#### Option 1: Automatic Build (Recommended)

```bash
cd /path/to/jwt-cpp
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build

# Run tests
ctest --test-dir build --output-on-failure
```

nkeys-cpp will be automatically fetched and built during configuration.

#### Option 2: Using System-Installed nkeys-cpp

If you prefer to use a system-installed version of nkeys-cpp:

```bash
# Install nkeys-cpp first
cd /path/to/nkeys-cpp
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
cmake --install build --prefix ~/local

# Build jwt-cpp with system nkeys-cpp
cd /path/to/jwt-cpp
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=~/local
cmake --build build
```

#### Build Options

- `JWT_USE_SYSTEM_NKEYS=ON` (default): Try system-installed nkeys-cpp first, fallback to FetchContent
- `JWT_USE_SYSTEM_NKEYS=OFF`: Always use FetchContent to build nkeys-cpp from source
- `JWT_WARNINGS_AS_ERRORS=ON`: Treat compiler warnings as errors
- `JWT_ENABLE_ASAN=ON`: Enable AddressSanitizer

**Example: Force FetchContent build**
```bash
cmake -S . -B build -DJWT_USE_SYSTEM_NKEYS=OFF
```

#### Build Performance

**First-time builds:** When using FetchContent (default), the first build takes ~90 seconds as it compiles nkeys-cpp from source. Subsequent builds are faster (~35 seconds) as the built library is cached.

**Tip:** If you frequently delete your build directory, consider installing nkeys-cpp to your system to speed up clean builds.

### Basic Usage (Coming Soon)

```cpp
#include <jwt/jwt.hpp>

// Create operator claims
auto op = jwt::OperatorClaims(operatorPublicKey);
op.setName("MyOperator");

// Encode to JWT
std::string jwt = op.encode(operatorSeed);

// Decode and verify
auto decoded = jwt::decodeOperatorClaims(jwt);
```

## Project Status

- [x] Bootstrap: Project structure created
- [x] Build System: CMake configuration with dependencies
- [x] Headers: All claim interfaces defined
- [x] Stubs: Minimal implementations compile and test
- [ ] Core: JWT encode/decode implementation
- [ ] Claims: Operator/Account/User claims
- [ ] Validation: Signature verification
- [ ] Utilities: Creds file formatting
- [ ] CLI Tool: jwt++ command-line utility
- [ ] Tests: Comprehensive test coverage
- [ ] Documentation: Complete API documentation

## Dependencies

- **nkeys-cpp**: Ed25519 cryptographic operations
- **nlohmann/json**: JSON serialization (header-only, auto-fetched)
- **GoogleTest**: Testing framework (auto-fetched)

## Requirements

- **Compiler**: C++20 support required
  - GCC 10+
  - Clang 12+
  - MSVC 19.29+ (Visual Studio 2019 16.10+)
- **CMake**: 3.20 or higher

## Architecture

### Trust Hierarchy

```
Operator (top-level)
  └─> Signs Account JWTs
       └─> Signs User JWTs
```

### Key Components

1. **Claims** (Base interface in `jwt/claims.hpp`)
   - `OperatorClaims`: Top-level organizational claims
   - `AccountClaims`: Tenant/workspace-level claims
   - `UserClaims`: End-user claims

2. **JWT Encoding/Decoding**
   - `encode()`: Claims → JWT string (signed with Ed25519)
   - `decode()`: JWT string → Claims (signature verified)

3. **Utilities**
   - `formatUserConfig()`: Generate NATS creds files
   - Signature verification helpers

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for development guidelines.

## Security

See [SECURITY.md](SECURITY.md) for security policy and reporting vulnerabilities.

## License

TBD - Compatible with nkeys-cpp and NATS JWT library licensing.

## Acknowledgments

- [NATS.io](https://nats.io/) for the original Go JWT implementation
- [nkeys-cpp](https://github.com/steve-weiland/nkeys-cpp) for Ed25519 operations
- [nlohmann/json](https://github.com/nlohmann/json) for JSON processing
