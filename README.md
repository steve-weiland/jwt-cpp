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
- nkeys-cpp library (from https://github.com/steve-weiland/nkeys-cpp)

### Building

```bash
# Install nkeys-cpp first (if not already installed)
cd /path/to/nkeys-cpp
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
cmake --install build --prefix ~/local

# Build jwt-cpp
cd /path/to/jwt-cpp
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=~/local
cmake --build build

# Run tests
ctest --test-dir build --output-on-failure
```

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
