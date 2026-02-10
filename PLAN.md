# Saltpack-Zig Port Plan

## Goal

Port the [saltpack](https://saltpack.org) cryptographic messaging format from Go
(ref/saltpack) to Zig, producing a production-worthy library built on Zig 0.15's
standard library crypto primitives.

## Architecture

### Module Layout

```
src/
├── saltpack.zig        # Root: public API surface, re-exports
├── basex.zig           # BaseX big-integer encoding (Base62 preset)
├── armor.zig           # Armor framing + Base62 streaming encode/decode
├── crypto.zig          # Thin wrappers over std.crypto (Box, SecretBox, Ed25519, HMAC)
├── nonce.zig           # Nonce construction for all saltpack contexts
├── header.zig          # Header encode/decode with double-encoding + hash
├── encrypt.zig         # Encryption seal/open (v1 + v2, streaming + one-shot)
├── decrypt.zig         # Decryption (v1 + v2, streaming + one-shot)
├── sign.zig            # Signing: attached + detached (v1 + v2, streaming)
├── verify.zig          # Verification: attached + detached (v1 + v2, streaming)
├── signcrypt.zig       # Signcryption seal/open (v2 only, streaming)
├── key.zig             # Key types, KeyRing interface (comptime interface pattern)
├── errors.zig          # Error sets and error context types
└── types.zig           # Version, MessageType, constants, RawBoxKey, SymmetricKey
```

### Dependencies

- **Crypto**: all from `std.crypto` (zero external crypto deps)
  - `std.crypto.nacl.Box` → NaCl crypto_box (Curve25519 + XSalsa20-Poly1305)
  - `std.crypto.nacl.SecretBox` → NaCl crypto_secretbox
  - `std.crypto.sign.Ed25519` → Ed25519 signing
  - `std.crypto.hash.sha2.Sha512` → SHA-512
  - `std.crypto.auth.hmac.sha2.HmacSha512` → HMAC-SHA512
- **MessagePack**: `zig-msgpack` (https://github.com/zigcc/zig-msgpack)
  - Provides `PackerIO` for streaming encode/decode via `std.Io.Reader`/`Writer`
  - `Payload` tagged union for constructing/inspecting values
  - Enforces minimal encoding automatically
  - Supports nil, bool, int, uint, str, bin, array, map
- **Big integer**: `std.math.big.int` for BaseX encoding

### Design Principles

1. **Zig-idiomatic**: use comptime interfaces (not vtables) for KeyRing, use error
   unions, use slices and fixed arrays, use allocator pattern
2. **Streaming-first**: all operations support streaming via Zig reader/writer patterns
3. **One-shot convenience**: wrap streaming APIs for single-call usage
4. **Const-correct**: leverage Zig's const semantics throughout
5. **Allocation-explicit**: accept `std.mem.Allocator`, never use global state
6. **Test-driven**: every module built test-first with spec-derived test vectors

---

## Work Packages

### WP1: BaseX Encoding (`basex.zig`) — FOUNDATION
**Estimated scope**: ~300 LOC + ~200 LOC tests
**Dependencies**: none
**Parallelizable with**: WP2

Implement BaseX encoding per the saltpack armor spec:

**Core:**
- Generic BaseX encoder/decoder parameterized by alphabet and block size
- Big-integer encode: B bytes → C characters (repeated div-mod by base)
- Big-integer decode: C characters → B bytes (Horner's method)
- Uses `std.math.big.int.Managed` for arithmetic on 32-byte blocks
- Validation: reject illegal blocks (overflow, non-minimal C for B)

**Presets:**
- `Base62` with alphabet `0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz`
- Input block: 32 bytes, output block: 43 characters

**Streaming:**
- `Encoder` wrapping a writer: accumulates input bytes, emits character blocks
- `Decoder` wrapping a reader: reads character blocks, emits decoded bytes
- Handle final short block correctly

**Tests:**
- Known vectors: `0x00` → `"00"`, `0xff` → `"3Y"`, 32 zero bytes → 43 `'0'`s
- Round-trip for random blocks of all sizes 1–32
- Illegal block detection
- Streaming round-trip with various buffer sizes

**Reference Go code:** `ref/saltpack/encoding/basex/`

---

### WP2: Common Types & Errors (`types.zig`, `errors.zig`, `key.zig`) — FOUNDATION
**Estimated scope**: ~200 LOC + ~100 LOC tests
**Dependencies**: none
**Parallelizable with**: WP1

**types.zig:**
- `Version` = struct { major: u32, minor: u32 } with `v1()` and `v2()` constructors
- `MessageType` = enum { encryption, attached_signature, detached_signature, signcryption }
- `RawBoxKey` = [32]u8
- `SymmetricKey` = [32]u8
- `PayloadKey` = [32]u8
- `Nonce` = [24]u8
- `HeaderHash` = [64]u8
- `MacKey` = [32]u8
- Constants: `encryption_block_size = 1 << 20` (1 MiB)

**errors.zig:**
- `SaltpackError` error set covering all failure modes
- Error context types (e.g., `BadCiphertext` with packet_seqno)

**key.zig:**
- `BoxPublicKey` / `BoxSecretKey` structs wrapping [32]u8
- `SigningPublicKey` / `SigningSecretKey` structs
- `BoxKeyPair` / `SigningKeyPair` combining pub+secret
- `KeyRing` comptime interface with required methods:
  - `lookupBoxSecretKey(kids: []const []const u8) ?BoxSecretKey`
  - `lookupBoxPublicKey(kid: []const u8) ?BoxPublicKey`
  - `getAllBoxSecretKeys() []const BoxSecretKey`
  - `importBoxEphemeralKey(kid: []const u8) ?BoxPublicKey`
- `SigKeyRing` comptime interface
- `SigncryptKeyRing` comptime interface
- Basic in-memory KeyRing implementation for testing

**Tests:**
- Version comparison and display
- MessageType encoding/decoding
- KeyRing basic operations
- Key serialization round-trips

**Reference Go code:** `ref/saltpack/const.go`, `ref/saltpack/key.go`, `ref/saltpack/errors.go`

---

### WP3: Nonce Construction (`nonce.zig`) — CORE
**Estimated scope**: ~150 LOC + ~150 LOC tests
**Dependencies**: WP2 (types)
**Parallelizable with**: WP4, WP8

Implement all saltpack nonce patterns:

- `senderKeyNonce()` → `"saltpack_sender_key_sbox"` (24 bytes, zero-padded)
- `payloadKeyBoxNonce(version, recipient_index)` → v1: fixed, v2: indexed
- `payloadNonce(block_number)` → `"saltpack_ploadsb" || uint64(n)`
- `macKeyNonce(version, header_hash, recipient_index)` → version-dependent
- `signcryptDerivedKeyNonce()` → `"saltpack_derived_sboxkey"`
- `signcryptPayloadNonce(header_hash, block_number, is_final)` → with LSB encoding
- `signatureNonce()` → 16 random bytes

**Tests:**
- Each nonce function produces correct byte pattern
- Cross-reference against Go implementation constants
- V1 vs V2 nonce differences verified

**Reference Go code:** `ref/saltpack/nonce.go`

---

### WP4: Header Codec (`header.zig`) — CORE
**Estimated scope**: ~400 LOC + ~300 LOC tests
**Dependencies**: WP2 (types), zig-msgpack
**Parallelizable with**: WP3, WP8

**Encoding:**
- `EncryptionHeader` struct → msgpack array → double-encode
- `SignatureHeader` struct → msgpack array → double-encode
- `SigncryptionHeader` (alias for EncryptionHeader)
- ReceiverKeys struct encoding
- Compute and return header hash (SHA-512 of inner encoding)

Uses `zig-msgpack` `PackerIO` to serialize header structs as msgpack arrays.
The double-encoding pattern: serialize header fields as a msgpack array to get
`headerBytes`, then serialize `headerBytes` as a msgpack bin to the wire.

**Decoding:**
- Read double-encoded header from reader
- Compute header hash during decode
- Parse into typed header structs via `PackerIO.read()` → `Payload` inspection
- Validate format name = "saltpack", version, message type

**Tests:**
- Round-trip encode/decode for each header type
- Header hash computation verified against known values
- Malformed header rejection (wrong format name, bad version, etc.)
- Cross-compat: encode in Zig, decode headers from Go-generated messages

**Reference Go code:** `ref/saltpack/packets.go`, `ref/saltpack/msgpack.go`

---

### WP5: Encryption/Decryption (`encrypt.zig`, `decrypt.zig`) — PROTOCOL
**Estimated scope**: ~600 LOC + ~500 LOC tests
**Dependencies**: WP2, WP3, WP4
**Parallelizable with**: WP6, WP7

**encrypt.zig:**
- `seal(allocator, version, plaintext, sender, receivers) -> []u8`
- `SealStream` writer type: header on first write, 1MiB chunks, final on close
- Receiver shuffling (Fisher-Yates with CSPRNG)
- MAC key derivation (v1 and v2 algorithms)
- Per-block authenticator computation (HMAC-SHA512 truncated to 32 bytes)
- Sender anonymity (nil sender → use ephemeral key)

**decrypt.zig:**
- `open(allocator, ciphertext, keyring) -> struct { sender, plaintext }`
- `OpenStream` reader type: streaming decryption
- Trial decryption for hidden recipients
- MAC verification per block
- Truncation detection (missing final block)
- V1 final = empty payload, V2 final = explicit flag

**Tests (TDD sequence):**
1. Encrypt empty message → decrypt → empty
2. Encrypt short message → decrypt → matches
3. Encrypt message > 1 MiB (multi-block) → decrypt → matches
4. Encrypt with multiple recipients → each can decrypt
5. Encrypt with anonymous sender → decrypt shows anonymous
6. Hidden recipients (empty KIDs) → trial decryption works
7. Tampered ciphertext → ErrBadCiphertext
8. Tampered authenticator → ErrBadTag
9. Truncated message → error
10. V1 ↔ V2 mode differences
11. **Cross-compat: decrypt Go-encrypted messages, Go decrypts Zig-encrypted**
12. Streaming encrypt → streaming decrypt round-trip

**Reference Go code:** `ref/saltpack/encrypt.go`, `ref/saltpack/decrypt.go`, `ref/saltpack/common.go`

---

### WP6: Signing/Verification (`sign.zig`, `verify.zig`) — PROTOCOL
**Estimated scope**: ~500 LOC + ~400 LOC tests
**Dependencies**: WP2, WP3, WP4
**Parallelizable with**: WP5, WP7

**sign.zig:**
- `sign(allocator, version, plaintext, signer) -> []u8` (attached)
- `signDetached(allocator, version, plaintext, signer) -> []u8`
- `SignStream` / `SignDetachedStream` writer types
- Per-chunk signature: `Ed25519_sign("saltpack attached signature\0" || hash)`
- Detached: single signature over entire message

**verify.zig:**
- `verify(allocator, signed_msg, keyring) -> struct { signer, plaintext }`
- `verifyDetached(allocator, message, signature, keyring) -> SigningPublicKey`
- `VerifyStream` / `VerifyDetachedStream` reader types
- Per-chunk signature verification
- Truncation detection

**Tests (TDD sequence):**
1. Sign empty message → verify → ok
2. Sign short message → verify → matches, correct signer
3. Sign multi-block message → verify → ok
4. Tampered payload → verification fails
5. Wrong key → verification fails
6. Detached sign → detached verify → ok
7. Detached sign → tampered message → fails
8. V1 ↔ V2 differences
9. Streaming sign → streaming verify
10. **Cross-compat: verify Go-signed messages, Go verifies Zig-signed**

**Reference Go code:** `ref/saltpack/sign.go`, `ref/saltpack/sign_stream.go`, `ref/saltpack/verify.go`, `ref/saltpack/verify_stream.go`

---

### WP7: Signcryption (`signcrypt.zig`) — PROTOCOL
**Estimated scope**: ~500 LOC + ~400 LOC tests
**Dependencies**: WP2, WP3, WP4
**Parallelizable with**: WP5, WP6

**signcrypt.zig:**
- `seal(allocator, plaintext, ephemeral_creator, sender, box_receivers, sym_receivers) -> []u8`
- `open(allocator, ciphertext, keyring, sym_resolver) -> struct { sender, plaintext }`
- `SealStream` / `OpenStream` types
- Two recipient types: Box (Curve25519 DH) and Symmetric (HMAC-derived)
- Payload = signature || plaintext, encrypted with secretbox
- Anonymous sender: zero signing key, zero signatures
- Nonce with LSB encoding finality

**Tests (TDD sequence):**
1. Signcrypt empty → open → empty, correct sender
2. Signcrypt short message → open → matches
3. Multi-block message → open → matches
4. Box recipients + symmetric recipients → both can open
5. Anonymous sender → open shows anonymous
6. Tampered ciphertext → fails
7. Truncated → fails
8. Streaming round-trip
9. **Cross-compat: open Go-signcrypted messages**

**Reference Go code:** `ref/saltpack/signcrypt_seal.go`, `ref/saltpack/signcrypt_open.go`

---

### WP8: Armor Layer (`armor.zig`) — PRESENTATION
**Estimated scope**: ~400 LOC + ~300 LOC tests
**Dependencies**: WP1 (basex), WP2 (types)
**Parallelizable with**: WP3, WP4

**armor.zig:**
- Frame parsing: header regex, footer matching
- `ArmorEncoder` stream: writes header frame → base62 words → footer frame
- `ArmorDecoder` stream: parses header → decodes base62 → validates footer
- Word formatting: space every 15 chars, newline every 200 words
- Brand support (optional 1-128 alphanumeric)
- Message type detection from frame
- Whitespace/quote-char stripping in decoder

**Tests (TDD sequence):**
1. Frame parse: "BEGIN SALTPACK ENCRYPTED MESSAGE." → correct type, no brand
2. Frame parse with brand: "BEGIN KEYBASE SALTPACK SIGNED MESSAGE."
3. Encode → decode round-trip (all message types)
4. Word/line formatting verification
5. Whitespace tolerance (extra spaces, tabs, > chars)
6. Invalid frame rejection
7. Brand validation (too long, invalid chars)
8. Streaming round-trip with various sizes
9. **Cross-compat: dearmor Go-armored messages**

**Reference Go code:** `ref/saltpack/armor.go`, `ref/saltpack/armor62.go`, `ref/saltpack/frame.go`

---

### WP9: Public API & Integration (`saltpack.zig`) — INTEGRATION
**Estimated scope**: ~300 LOC + ~500 LOC tests
**Dependencies**: ALL previous WPs
**Parallelizable with**: nothing (final phase)

**saltpack.zig (root module):**
- Re-export public types and functions
- `classifyStream()` → detect armored/binary, message type, version
- `Armor62Seal` / `Armor62Open` convenience functions
- Armored variants for encrypt/decrypt/sign/verify/signcrypt
- Version validation helpers

**Integration tests:**
- Full end-to-end: plaintext → armor62 encrypt → armor62 decrypt → plaintext
- Full signing workflow: sign → armor → dearmor → verify
- Message classification on all types
- **Cross-compatibility test suite**: generate test vectors with Go, verify with Zig and vice versa
- Fuzz testing: random inputs to decoder/dearmor paths
- Performance benchmarks

**Reference Go code:** `ref/saltpack/classify_and_decrypt.go`, `ref/saltpack/armor62_*.go`

---

## Development Phases & Agent Assignment

```
Phase 0 — Foundation (parallel)       Phase 1 — Core (parallel)
┌──────────────┐                      ┌──────────────┐
│ Agent A: WP1 │                      │ Agent C: WP3 │
│ (basex)      │──┐                   │ (nonce)      │
└──────────────┘  │                   └──────────────┘
┌──────────────┐  ├→ Phase 1 gate →  ┌──────────────┐
│ Agent B: WP2 │──┘                   │ Agent D: WP4 │
│ (types/keys) │                      │ (header)     │
└──────────────┘                      └──────────────┘
                                      ┌──────────────┐
                                      │ Agent E: WP8 │
                                      │ (armor)      │
                                      └──────────────┘

Phase 2 — Protocol (parallel)         Phase 3 — Integration
┌──────────────┐                      ┌──────────────┐
│ Agent F: WP5 │                      │ Agent I: WP9 │
│ (encrypt)    │                      │ (public API) │
└──────────────┘                      └──────────────┘
┌──────────────┐
│ Agent G: WP6 │
│ (signing)    │
└──────────────┘
┌──────────────┐
│ Agent H: WP7 │
│ (signcrypt)  │
└──────────────┘
```

### Phase 0: Foundation (2 agents in parallel)
- **Agent A**: WP1 — BaseX encoding
- **Agent B**: WP2 — Types, errors, key interfaces

### Phase 1: Core Infrastructure (3 agents in parallel)
- **Agent C**: WP3 — Nonce construction
- **Agent D**: WP4 — Header codec
- **Agent E**: WP8 — Armor layer

### Phase 2: Protocol Implementation (3 agents in parallel)
- **Agent F**: WP5 — Encryption/Decryption
- **Agent G**: WP6 — Signing/Verification
- **Agent H**: WP7 — Signcryption

### Phase 3: Integration (1 agent)
- **Agent I**: WP9 — Public API, integration tests, cross-compat

---

## TDD Workflow (per agent)

Each agent follows this cycle:

1. **Read the spec** — relevant section from `ref/saltpack/specs/`
2. **Read the Go code** — corresponding Go file for implementation reference
3. **Write failing test** — test the simplest case first
4. **Write minimal code** — make the test pass
5. **Refactor** — clean up while tests stay green
6. **Next test** — increase complexity, add edge cases
7. **Run `zig build test`** — ensure all tests pass before moving on

---

## Cross-Compatibility Testing Strategy

1. **Generate test vectors from Go**: Write a small Go program that produces known
   encrypt/sign/signcrypt/armor outputs with fixed keys and plaintexts
2. **Embed vectors in Zig tests**: Use `@embedFile` to load Go-generated test data
3. **Verify Zig can decode Go output**: Decrypt, verify, dearmor Go messages
4. **Verify Go can decode Zig output**: (Optional, run Go tests against Zig output)

---

## Conventions

- **File naming**: snake_case matching module names
- **Test naming**: `test "descriptive name of behavior"`
- **Error handling**: return error unions, never panic in library code
- **Allocation**: accept `std.mem.Allocator` parameter, caller owns memory
- **Const correctness**: prefer `const` everywhere possible
- **No global state**: all state in structs passed explicitly
- **Doc comments**: `///` on all public functions and types
