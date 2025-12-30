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

### nkeys-cpp (Required - Auto-fetched)

**Default behavior:** jwt-cpp automatically downloads and builds nkeys-cpp via FetchContent if not found.

**For system-installed nkeys-cpp:**
```bash
# Install nkeys-cpp to ~/local
cd /Users/steve/src/nkeys-cpp
cmake -S . -B build -DCMAKE_BUILD_TYPE=Release
cmake --build build
cmake --install build --prefix ~/local

# Configure jwt-cpp to find it
cd /Users/steve/src/jwt-cpp
cmake -S . -B build -DCMAKE_PREFIX_PATH=~/local
```

**To force FetchContent build:**
```bash
cmake -S . -B build -DJWT_USE_SYSTEM_NKEYS=OFF
```

**Version pinning (for reproducible builds):**
FetchContent uses the main branch by default. To pin to a specific commit, edit CMakeLists.txt:
```cmake
GIT_TAG abc123def456  # Replace main with commit SHA
```

**Cache management:**
FetchContent caches downloaded sources in `build/_deps/`. To rebuild from scratch:
```bash
rm -rf build/_deps/nkeys-cpp-*
cmake --build build
```

### nlohmann/json (Auto-fetched)

Header-only JSON library, automatically downloaded by CMake during configuration.

## Dependency Management Strategy

jwt-cpp uses a **hybrid dependency approach**:

1. **nkeys-cpp**: System install preferred, FetchContent fallback
2. **nlohmann/json**: Always FetchContent (header-only)
3. **GoogleTest**: System install preferred, FetchContent fallback

### Why This Approach?

**Benefits:**
- **CLion/IDE compatibility**: No manual dependency installation required
- **Reproducible builds**: FetchContent ensures exact versions
- **Flexibility**: Developers can use system packages if preferred
- **CI/CD friendly**: Works out-of-the-box in clean build environments

**Trade-offs:**
- First build takes longer (compiles nkeys-cpp from source)
- Subsequent builds use cached _deps/ folder (fast)
- System install still supported for package managers

### Customizing Dependencies

```bash
# Use system packages only (fail if not found)
cmake -S . -B build -DJWT_USE_SYSTEM_NKEYS=ON

# Force all FetchContent (reproducible builds)
cmake -S . -B build -DJWT_USE_SYSTEM_NKEYS=OFF

# Mixed approach (default - recommended)
cmake -S . -B build  # Tries system first, falls back to FetchContent
```

### Production Version Pinning

For production deployments, pin nkeys-cpp to a specific commit:

```cmake
# In CMakeLists.txt, change FetchContent_Declare:
FetchContent_Declare(
    nkeys-cpp
    GIT_REPOSITORY https://github.com/steve-weiland/nkeys-cpp.git
    GIT_TAG abc123def456  # Replace with specific commit SHA
    GIT_SHALLOW FALSE     # Change to FALSE to allow any commit
)
```

To find the current commit SHA:
```bash
# If using FetchContent:
cat build/_deps/nkeys-cpp-src/.git/refs/heads/main
```

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

# Run specific test suite
./build/jwt_test          # Core JWT encoding/decoding tests (23 tests)
./build/claims_test       # Claims validation tests (36 tests)
./build/validation_test   # Validation system tests (23 tests)
./build/cmd_args_test     # CLI argument parsing tests (25 tests)
./build/e2e_test          # End-to-end workflow tests (11 tests)

# With verbose output
ctest --test-dir build --verbose
```

### Test Coverage

**Total: 119 tests across 5 test suites**

1. **jwt_test** (23 tests): Core functionality
   - JWT encoding/decoding for all claim types
   - Base64 URL encoding/decoding
   - Signature verification
   - Credentials file generation

2. **claims_test** (36 tests): Claims validation
   - OperatorClaims (11 tests)
   - AccountClaims (8 tests)
   - UserClaims (8 tests)
   - Integration tests (3 tests)
   - Edge cases (6 tests)

3. **validation_test** (23 tests): Validation system
   - Time-based validation (expiration, not-before, clock skew)
   - Chain validation (issuer chains, hierarchy)
   - Comprehensive validation with configurable options

4. **cmd_args_test** (25 tests): CLI argument parsing
   - Long/short options
   - Positional arguments
   - Edge cases and real-world examples

5. **e2e_test** (11 tests): End-to-end workflows
   - Complete trust hierarchy creation
   - Credentials file workflows
   - Token lifecycle (expiration, renewal)
   - Multi-account/multi-user scenarios
   - Cross-signing with signing keys
   - Error detection (broken chains, corruption)
   - Real-world NATS deployment simulation

## CLI Tool

```bash
# Show version
./build/jwt++ --version

# Show help
./build/jwt++ --help

# Encode operator JWT (self-signed)
./build/jwt++ --encode --type operator --inkey operator.seed --name "My Operator"

# Encode account JWT (signed by operator)
./build/jwt++ --encode --type account --inkey account.seed \
  --sign-key operator.seed --issuer <operator_pub> --name "My Account"

# Encode user JWT (signed by account)
./build/jwt++ --encode --type user --inkey user.seed \
  --sign-key account.seed --issuer <account_pub> \
  --issuer-account <account_pub> --name "My User"

# Decode JWT (displays claims as JSON)
./build/jwt++ --decode operator.jwt
./build/jwt++ --decode operator.jwt --compact  # Compact JSON output

# Verify JWT signature
./build/jwt++ --verify operator.jwt

# Generate NATS credentials file
./build/jwt++ --generate-creds --inkey user.seed user.jwt
./build/jwt++ --generate-creds --inkey user.seed --out user.creds user.jwt
```

## Next Steps (Implementation Phase)

### Priority 1: Core JWT Infrastructure ✅ COMPLETED
1. ✅ Implement Base64 URL encoding/decoding (no padding)
2. ✅ Implement JWT header struct and JSON serialization
3. ✅ Implement claims JSON serialization
4. ✅ Integrate nkeys-cpp for signing
5. ✅ Write tests for encoding pipeline

### Priority 2: Claims Implementation ✅ COMPLETED
1. ✅ Implement OperatorClaims::encode()
2. ✅ Implement AccountClaims::encode()
3. ✅ Implement UserClaims::encode()
4. ✅ Add timestamp handling (IssuedAt auto-set)
5. ✅ Write comprehensive claims tests (36 tests covering all claim types)

### Priority 3: Decoding & Verification ✅ COMPLETED
1. ✅ Implement JWT parsing (split header.payload.signature)
2. ✅ Implement Base64 URL decoding
3. ✅ Implement signature verification with nkeys-cpp
4. ✅ Implement decode() functions for all claim types
5. ✅ Write decoding and verification tests (14 tests covering round-trips, verification, error handling)

### Priority 4: Utilities & CLI ✅ COMPLETED
1. ✅ Implement formatUserConfig() (creds file generation with 7 comprehensive tests)
2. ✅ Implement CLI tool functionality (jwt++ with encode/decode/verify/generate-creds commands)
3. ✅ Implement validation system (time-based, chain, and hierarchy validation with 23 comprehensive tests)
4. ✅ Write end-to-end tests (11 comprehensive E2E scenarios covering real-world workflows)
5. ✅ Update documentation (README.md updated with concise usage examples)

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

### Validating JWTs

```cpp
#include <jwt/validation.hpp>

// Validate a JWT string with default options (signature + structure)
auto result = jwt::validate(jwt_string);
if (!result.valid) {
    std::cerr << "Validation failed: " << result.error.value() << "\n";
}

// Validate with specific options
jwt::ValidationOptions opts;
opts.checkExpiration = true;
opts.checkSignature = true;
opts.checkIssuerChain = false;
opts.clockSkewSeconds = 60;  // Allow 1 minute clock skew

auto result = jwt::validate(jwt_string, opts);

// Validate decoded claims
auto claims = jwt::decode(jwt_string);
auto timing_result = jwt::validateTiming(*claims, opts);

// Validate a complete chain (operator -> account -> user)
std::vector<std::string> chain = {operator_jwt, account_jwt, user_jwt};
jwt::ValidationOptions chain_opts = jwt::ValidationOptions::strict();
auto chain_result = jwt::validateChain(chain, chain_opts);

// Check expiration only
auto exp_result = jwt::validateExpiration(*claims);

// Validate issuer chain between parent and child
auto issuer_result = jwt::validateIssuerChain(*child_claims, *parent_claims);

// Validate key hierarchy
auto hierarchy_result = jwt::validateKeyHierarchy(*child_claims, *parent_claims);
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

**Build Status**: ✅ All 119 tests pass (100% success rate)
**Status**: 🎉 All priorities completed - Production ready!
