# Claude Code Guide: jwt-cpp

This document helps Claude Code (AI assistant) understand the jwt-cpp project.

## Project Overview

**jwt-cpp** is a C++ port of the Go NATS JWT library. It provides JWT encoding/decoding for NATS authentication using Ed25519 signatures.

**Status:** Bootstrap phase complete, ready for core implementation.

## Build Commands

```bash
# Configure and build (assuming nkeys-cpp is installed to ~/local)
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release -DCMAKE_PREFIX_PATH=~/local
cmake --build build

# Run tests
ctest --test-dir build --output-on-failure

# Development build with sanitizers
cmake -S . -B build \
    -DCMAKE_BUILD_TYPE=Debug \
    -DJWT_ENABLE_ASAN=ON \
    -DJWT_WARNINGS_AS_ERRORS=ON \
    -DCMAKE_PREFIX_PATH=~/local
cmake --build build
ctest --test-dir build
```

## Dependencies

### nkeys-cpp (Required)

Must be installed before building jwt-cpp. If not in standard locations, set `CMAKE_PREFIX_PATH`:

```bash
# From /Users/steve/src/nkeys-cpp
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
cmake --install build --prefix ~/local

# Then use it in jwt-cpp
export CMAKE_PREFIX_PATH=~/local
```

Or on macOS with standard install:
```bash
cmake --install build  # Installs to /usr/local
```

### nlohmann/json (Auto-fetched)

Header-only JSON library, automatically downloaded by CMake during configuration.

## Architecture

### Trust Hierarchy

```
Operator (top-level)
  └─> Signs Account JWTs
       └─> Signs User JWTs
```

Each level can sign JWTs for the level below:
- **Operator**: Signs account JWTs, manages signing keys
- **Account**: Signs user JWTs, manages signing keys
- **User**: Signed by account, authenticates to NATS

### Key Components

1. **Claims** (Base interface: `include/jwt/claims.hpp`)
   - Pure virtual interface defining common JWT operations
   - `subject()`: Public key of claim holder
   - `issuer()`: Public key of signer
   - `encode()`: Generate signed JWT string
   - `validate()`: Verify claim structure

2. **OperatorClaims** (`include/jwt/operator_claims.hpp`, `src/operator_claims.cpp`)
   - Top-level organizational claims
   - Can add multiple signing keys for account signing
   - Self-signed (subject == issuer)

3. **AccountClaims** (`include/jwt/account_claims.hpp`, `src/account_claims.cpp`)
   - Tenant/workspace-level claims
   - Signed by operator
   - Can add signing keys for user signing

4. **UserClaims** (`include/jwt/user_claims.hpp`, `src/user_claims.cpp`)
   - End-user authentication claims
   - Signed by account
   - Used in NATS creds files

### File Structure

```
include/jwt/       # Public API headers
  jwt.hpp          # Main header (includes all)
  jwt_constants.hpp # Constants (version, algorithm, limits)
  claims.hpp        # Base Claims interface
  operator_claims.hpp
  account_claims.hpp
  user_claims.hpp

src/              # Implementation
  jwt.cpp         # Core decode/verify functions
  claims.cpp      # Base class (minimal)
  operator_claims.cpp
  account_claims.cpp
  user_claims.cpp
  tools/
    jwt-main.cpp  # CLI executable
    cmd_args.hpp  # Argument parser (from nkeys-cpp)

tests/            # GoogleTest tests
  jwt_test.cpp
  claims_test.cpp
  cmd_args_test.cpp
  fixtures/       # Test data (to be added)
```

## Implementation Notes

- **C++ Standard**: C++20 (for std::span, std::optional, concepts)
- **Error Handling**: Exceptions (std::invalid_argument, std::runtime_error)
- **Memory Safety**: RAII, smart pointers (std::unique_ptr)
- **Pimpl Pattern**: All claims classes use pimpl for ABI stability
- **JSON**: nlohmann/json for serialization (`#include <nlohmann/json.hpp>`)
- **Crypto**: nkeys-cpp for Ed25519 operations (`#include <nkeys/nkeys.hpp>`)

### JWT Structure

Standard JWT format: `header.payload.signature` (Base64 URL encoded)

**Header**:
```json
{
  "typ": "JWT",
  "alg": "ed25519-nkey"
}
```

**Payload** (example for operator):
```json
{
  "jti": "<unique-id>",
  "iat": 1234567890,
  "iss": "<operator-public-key>",
  "sub": "<operator-public-key>",
  "nats": {
    "type": "operator",
    "version": 2,
    "signing_keys": ["<key1>", "<key2>"]
  }
}
```

### Base64 URL Encoding

JWT uses Base64 URL encoding (RFC 4648) **without padding**:
- Replace `+` with `-`
- Replace `/` with `_`
- Remove trailing `=` padding

## Testing

```bash
# Run all tests
ctest --test-dir build --output-on-failure

# Run specific test
./build/jwt_test
./build/claims_test

# With verbose output
ctest --test-dir build --verbose
```

## CLI Tool

```bash
# Current functionality (minimal stub)
./build/jwt++ --version
./build/jwt++ --help

# Planned functionality:
./build/jwt++ --encode operator.json --inkey operator.seed
./build/jwt++ --decode operator.jwt
./build/jwt++ --verify operator.jwt --pubin operator.pub
```

## Next Steps (Implementation Phase)

### Priority 1: Core JWT Infrastructure
1. Implement Base64 URL encoding/decoding (no padding)
2. Implement JWT header struct and JSON serialization
3. Implement claims JSON serialization
4. Integrate nkeys-cpp for signing
5. Write tests for encoding pipeline

### Priority 2: Claims Implementation
1. Implement OperatorClaims::encode()
2. Implement AccountClaims::encode()
3. Implement UserClaims::encode()
4. Add timestamp handling (IssuedAt auto-set)
5. Write comprehensive claims tests

### Priority 3: Decoding & Verification
1. Implement JWT parsing (split header.payload.signature)
2. Implement Base64 URL decoding
3. Implement signature verification with nkeys-cpp
4. Implement decode() functions for all claim types
5. Write decoding and verification tests

### Priority 4: Utilities & CLI
1. Implement formatUserConfig() (creds file generation)
2. Implement CLI tool functionality
3. Add validation system
4. Write end-to-end tests
5. Update documentation

## Common Patterns

### Creating Claims

```cpp
// Operator
auto op = jwt::OperatorClaims("OABC..."); // operator public key
op.setName("MyOperator");
op.setExpires(expirationTimestamp);
op.addSigningKey("ODEF..."); // additional signing key
```

### Encoding Claims

```cpp
std::string operatorSeed = "SOABC..."; // Ed25519 seed
std::string jwt = op.encode(operatorSeed);
// Returns: "eyJ...header...eyJ...payload...signature"
```

### Decoding Claims

```cpp
auto decoded = jwt::decodeOperatorClaims(jwt);
std::cout << decoded->subject() << "\n";
std::cout << decoded->name().value_or("(unnamed)") << "\n";
```

### Using nkeys-cpp

```cpp
#include <nkeys/nkeys.hpp>

// Load keypair
auto kp = nkeys::fromSeed(seed);

// Sign data
auto signature = kp->sign(data);

// Verify signature
bool valid = nkeys::verify(publicKey, data, signature);
```

## Reference

- **Go JWT Library**: https://github.com/nats-io/jwt
- **nkeys-cpp**: https://github.com/steve-weiland/nkeys-cpp (local: /Users/steve/src/nkeys-cpp)
- **nlohmann/json**: https://github.com/nlohmann/json
- **NATS Documentation**: https://docs.nats.io/

## Bootstrap Summary

The jwt-cpp project has been successfully bootstrapped with:

- ✅ Complete directory structure
- ✅ CMake build system with dependency management
- ✅ All header files with correct interfaces
- ✅ Compilable stub implementations (throw "not implemented")
- ✅ GoogleTest integration with 27 passing tests
- ✅ CLI tool skeleton (jwt++)
- ✅ Documentation (README, CLAUDE, CONTRIBUTING, SECURITY)
- ✅ Git repository initialized

**Build Status**: ✅ All tests pass (27/27)
**Next Action**: Begin implementing core JWT encoding/decoding functionality
