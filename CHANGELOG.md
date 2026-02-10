# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com),
and this project adheres to [Semantic Versioning](https://semver.org).

## [0.1.0] - Unreleased (and Vibed)

### Added

- Core saltpack operations: encrypt/decrypt, sign/verify (attached and detached), signcrypt/open
- Saltpack version 1 and version 2 format support
- Streaming APIs: `EncryptStream`, `DecryptStream`, `SignStream`, `VerifyStream`
- BaseX armor/dearmor (Base62) with branded header support
- Version policy enforcement (`VersionPolicy` for downgrade protection)
- Sender identity verification helpers (`verifyAttachedFrom`/`verifyDetachedFrom`, `signcryptOpenFrom`)
- Safe error mapping (`toSafeError`) for server contexts
- Comprehensive test suite (365+ tests)
- Benchmark suite (`zig build bench`)
- Cross-compatibility with Go saltpack reference implementation

### Security

- Timing-safe key comparisons throughout
- Secure key zeroing (`wipe()` on key pairs)
- Full buffer zeroing on stream cleanup
- 32-byte signature nonces per spec
- Anonymous sender signature verification in signcrypt
