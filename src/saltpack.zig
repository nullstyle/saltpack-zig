//! Saltpack: a modern crypto messaging format.
//!
//! This is a Zig port of the saltpack format (https://saltpack.org),
//! originally implemented in Go by Keybase.
//!
//! ## Quick Start
//!
//! ```zig
//! const sp = @import("saltpack");
//!
//! // Encryption
//! const ct = try sp.seal(allocator, "hello", sender.secret_key, &.{receiver.public_key}, .{});
//! defer allocator.free(ct);
//! const result = try sp.open(allocator, ct, &.{receiver});
//! defer result.deinit();
//!
//! // Signing (attached)
//! const signed = try sp.signAttached(allocator, "hello", signer.secret_key, .{});
//! defer signed.deinit();
//! const verified = try sp.verifyAttached(allocator, signed.data);
//! defer verified.deinit();
//! ```
//!
//! ## Thread Safety
//!
//! **One-shot APIs** (`seal`, `open`, `signAttached`, `signDetached`,
//! `verifyAttached`, `verifyDetached`, `signcryptSeal`, `signcryptOpen`,
//! and their armored/WithOptions variants) are **thread-safe**: each call
//! operates on its own stack and heap state with no shared mutable data,
//! so multiple threads may invoke them concurrently without synchronization.
//!
//! **Stream instances** (`EncryptStream`, `DecryptStream`, `SignStream`,
//! `VerifyStream`) are **NOT thread-safe**. Each stream holds mutable
//! internal buffers, block counters, and cryptographic state. A single
//! stream instance must not be shared between threads. If concurrent
//! streaming is required, create a separate stream instance per thread.

const std = @import("std");
const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// Submodules
// ---------------------------------------------------------------------------

const basex = @import("basex.zig");
const types = @import("types.zig");
const errors = @import("errors.zig");
const key = @import("key.zig");
const nonce = @import("nonce.zig");
const header = @import("header.zig");
const armor = @import("armor.zig");
const encrypt = @import("encrypt.zig");
const decrypt = @import("decrypt.zig");
const sign = @import("sign.zig");
const verify = @import("verify.zig");
const signcrypt = @import("signcrypt.zig");
pub const stream = @import("stream.zig");

// ---------------------------------------------------------------------------
// Re-exported types
// ---------------------------------------------------------------------------

/// A saltpack protocol version (major.minor).
pub const Version = types.Version;
/// Policy for restricting which protocol versions are accepted during verification.
pub const VersionPolicy = types.VersionPolicy;
/// Comprehensive error set for all saltpack operations.
pub const Error = errors.Error;
/// Metadata about which key was used for decryption and who the sender was.
pub const MessageKeyInfo = errors.MessageKeyInfo;

/// A NaCl Box public key (Curve25519, 32 bytes).
pub const BoxPublicKey = key.BoxPublicKey;
/// A NaCl Box secret key (Curve25519, 32 bytes).
pub const BoxSecretKey = key.BoxSecretKey;
/// A NaCl Box key pair (Curve25519 public + secret key).
pub const BoxKeyPair = key.BoxKeyPair;
/// An Ed25519 signing public key (32 bytes).
pub const SigningPublicKey = key.SigningPublicKey;
/// An Ed25519 signing secret key (64 bytes).
pub const SigningSecretKey = key.SigningSecretKey;
/// An Ed25519 signing key pair (public + secret key).
pub const SigningKeyPair = key.SigningKeyPair;

/// Options for encryption operations (e.g. protocol version selection).
pub const SealOptions = encrypt.SealOptions;
/// Options for decryption operations (e.g. version policy enforcement).
pub const OpenOptions = decrypt.OpenOptions;
/// Result of a decryption operation: plaintext and key metadata.
pub const OpenResult = decrypt.OpenResult;
/// Options for signing operations (e.g. protocol version selection).
pub const SignOptions = sign.SignOptions;
/// Result of a signing operation: the serialized signed message bytes.
pub const SignResult = sign.SignResult;
/// Result of attached-signature verification: signer public key and plaintext.
pub const VerifyResult = verify.VerifyResult;
/// Result of detached-signature verification: signer public key.
pub const VerifyDetachedResult = verify.VerifyDetachedResult;
/// Options for controlling which signers and versions are accepted during verification.
pub const VerifyOptions = verify.VerifyOptions;
/// Options for signcryption seal operations (receivers, version).
pub const SigncryptSealOptions = signcrypt.SealOptions;
/// Options for signcryption open operations (symmetric keys).
pub const SigncryptOpenOptions = signcrypt.OpenOptions;
/// Result of opening a signcrypted message: plaintext and key metadata.
pub const SigncryptOpenResult = signcrypt.OpenResult;
/// A symmetric key paired with an identifier, for use as a signcryption recipient.
pub const ReceiverSymmetricKey = signcrypt.ReceiverSymmetricKey;

/// Streaming encryption writer that encrypts plaintext block-by-block.
pub const EncryptStream = stream.EncryptStream;
/// Streaming decryption reader that decrypts ciphertext block-by-block.
pub const DecryptStream = stream.DecryptStream;
/// Streaming signing writer that creates attached signatures block-by-block.
pub const SignStream = stream.SignStream;
/// Streaming verification reader that verifies signed messages block-by-block.
pub const VerifyStream = stream.VerifyStream;

// ---------------------------------------------------------------------------
// Safe error mapping (error oracle / information leakage mitigation)
// ---------------------------------------------------------------------------

/// A reduced error category safe to expose to untrusted callers.
///
/// Detailed saltpack errors (e.g. `NoDecryptionKey`, `BadCiphertext`,
/// `BadSignature`) reveal how far message processing progressed, which can
/// help an attacker mount an error oracle attack. This enum collapses all
/// internal errors into four opaque categories that do not leak processing
/// progress.
///
/// ## Usage
///
/// ```zig
/// const result = sp.open(allocator, ct, &keyring) catch |err| {
///     log.err("internal: {}", .{err}); // log details for debugging
///     return sp.toSafeError(err);       // return opaque error to client
/// };
/// ```
pub const SafeError = enum {
    /// A decryption operation failed. Returned for all errors arising from
    /// `open`, `openWithOptions`, `signcryptOpen`, `signcryptOpenWithOptions`,
    /// and their armored variants when the input is structurally valid
    /// saltpack but decryption/authentication does not succeed.
    decryption_failed,

    /// A signature verification operation failed. Returned for all errors
    /// arising from `verifyAttached`, `verifyDetached`, and their variants
    /// when the input is structurally valid saltpack but the signature does
    /// not verify.
    verification_failed,

    /// The input was not valid saltpack (malformed framing, wrong message
    /// type, bad encoding, etc.).
    invalid_input,

    /// An internal or unexpected error (e.g. out of memory, allocator
    /// failure). Callers should treat this as an opaque server-side error.
    internal_error,
};

/// Map any error returned by a saltpack operation to a `SafeError` that is
/// safe to expose to untrusted parties.
///
/// This function is intentionally conservative: every `errors.Error` variant
/// maps to one of the four `SafeError` categories, and any unrecognized
/// error (e.g. `OutOfMemory` from the allocator) maps to `internal_error`.
///
/// **Guidance:** Log the original error for debugging, then return only the
/// `SafeError` to the caller. This prevents error oracles while preserving
/// full diagnostics in server logs.
pub fn toSafeError(err: anyerror) SafeError {
    return switch (err) {
        // -- Decryption path errors → decryption_failed -----------------------
        error.NoDecryptionKey,
        error.BadSenderKeySecretbox,
        error.DecryptionFailed,
        error.BadCiphertext,
        error.NoSenderKey,
        => .decryption_failed,

        // -- Verification path errors → verification_failed -------------------
        error.BadSignature,
        error.UntrustedSigner,
        error.UnexpectedSigner,
        => .verification_failed,

        // -- Input validation errors → invalid_input --------------------------
        error.BadVersion,
        error.WrongMessageType,
        error.BadFrame,
        error.NotASaltpackMessage,
        error.BadEphemeralKey,
        error.TrailingGarbage,
        error.PacketOverflow,
        error.UnexpectedEmptyBlock,
        error.FailedToReadHeaderBytes,
        error.BadBoxKey,
        error.TruncatedMessage,
        error.TooManyReceivers,
        error.BadReceivers,
        error.RepeatedKey,
        error.VersionNotAllowed,
        error.BadPublicKey,
        error.BadSecretKey,
        // Armor errors (BadFrame already covered above)
        armor.Error.FrameMismatch,
        armor.Error.Truncated,
        => .invalid_input,

        // -- Everything else (OutOfMemory, etc.) → internal_error -------------
        else => .internal_error,
    };
}

// ---------------------------------------------------------------------------
// Encryption convenience API
// ---------------------------------------------------------------------------

/// Encrypt a plaintext message for the given receivers.
///
/// `sender` is the sender's Box secret key. Pass null for anonymous mode.
/// Returns encrypted bytes (caller must free with allocator).
pub fn seal(
    allocator: Allocator,
    plaintext: []const u8,
    sender: ?BoxSecretKey,
    receivers: []const BoxPublicKey,
    opts: SealOptions,
) ![]u8 {
    return encrypt.seal(allocator, plaintext, sender, receivers, opts);
}

/// Decrypt an encrypted saltpack message.
///
/// Returns the decrypted plaintext and key metadata. Caller owns the result
/// and must call `result.deinit()` to free the plaintext.
///
/// This is the backward-compatible entry point (accepts any protocol version).
/// To enforce a version policy (e.g. reject V1 messages), use `openWithOptions`.
///
/// **Security warning:** On failure this function returns specific error codes
/// (e.g. `NoDecryptionKey`, `DecryptionFailed`, `BadVersion`) that reveal how
/// far processing progressed. When used in a server or API context, propagating
/// these errors to untrusted callers creates an *error oracle* that can aid
/// cryptographic attacks. Use `toSafeError()` to collapse detailed errors into
/// a generic `SafeError` before returning them to untrusted parties.
pub fn open(
    allocator: Allocator,
    ciphertext: []const u8,
    keyring: []const BoxKeyPair,
) !OpenResult {
    return decrypt.open(allocator, ciphertext, keyring, .{});
}

/// Decrypt an encrypted saltpack message with caller-specified options.
///
/// Use `opts.version_policy` to restrict which protocol versions are accepted.
/// For example, pass `.{ .version_policy = VersionPolicy.v2Only() }` to reject
/// V1 messages and defend against version downgrade attacks.
///
/// Returns the decrypted plaintext and key metadata. Caller owns the result
/// and must call `result.deinit()` to free the plaintext.
///
/// **Security warning:** On failure this function returns specific error codes
/// that reveal how far processing progressed. When used in a server or API
/// context, use `toSafeError()` to collapse these into a generic `SafeError`
/// before returning them to untrusted parties. See `open()` for details.
pub fn openWithOptions(
    allocator: Allocator,
    ciphertext: []const u8,
    keyring: []const BoxKeyPair,
    opts: OpenOptions,
) !OpenResult {
    return decrypt.open(allocator, ciphertext, keyring, opts);
}

// ---------------------------------------------------------------------------
// Signing convenience API
// ---------------------------------------------------------------------------

/// Create an attached signature of plaintext.
pub fn signAttached(
    allocator: Allocator,
    plaintext: []const u8,
    signer: SigningSecretKey,
    opts: SignOptions,
) !SignResult {
    return sign.sign(allocator, plaintext, signer, opts);
}

/// Create a detached signature of plaintext.
pub fn signDetached(
    allocator: Allocator,
    plaintext: []const u8,
    signer: SigningSecretKey,
    opts: SignOptions,
) !SignResult {
    return sign.signDetached(allocator, plaintext, signer, opts);
}

/// Verify an attached signature message. Returns the signer and plaintext.
///
/// WARNING: This function does NOT authenticate the signer's identity. It
/// only checks that the embedded signature is valid for the embedded public
/// key. An attacker can create a validly signed message with any key they
/// control. To verify that the message came from a specific trusted signer,
/// use `verifyAttachedWithOptions` with the `trusted_signers` field set.
///
/// **Security warning:** On failure this function returns specific error codes
/// (e.g. `BadSignature`, `WrongMessageType`, `TruncatedMessage`) that reveal
/// how far processing progressed. When used in a server or API context, use
/// `toSafeError()` to collapse these into a generic `SafeError` before
/// returning them to untrusted parties.
pub fn verifyAttached(
    allocator: Allocator,
    signed_msg: []const u8,
) !VerifyResult {
    return verify.verify(allocator, signed_msg);
}

/// Verify an attached signature message with caller-specified options.
/// Use `opts.trusted_signers` to restrict accepted signing keys and
/// `opts.version_policy` to restrict accepted protocol versions.
pub fn verifyAttachedWithOptions(
    allocator: Allocator,
    signed_msg: []const u8,
    opts: VerifyOptions,
) !VerifyResult {
    return verify.verifyWithOptions(allocator, signed_msg, opts);
}

/// Verify a detached signature. Returns the signer's public key.
///
/// WARNING: This function does NOT authenticate the signer's identity. It
/// only checks that the embedded signature is valid for the embedded public
/// key. An attacker can create a validly signed message with any key they
/// control. To verify that the message came from a specific trusted signer,
/// use `verifyDetachedWithOptions` with the `trusted_signers` field set.
///
/// **Security warning:** On failure this function returns specific error codes
/// that reveal how far processing progressed. When used in a server or API
/// context, use `toSafeError()` to collapse these into a generic `SafeError`
/// before returning them to untrusted parties. See `verifyAttached()` for details.
pub fn verifyDetached(
    allocator: Allocator,
    message: []const u8,
    signature_msg: []const u8,
) !VerifyDetachedResult {
    return verify.verifyDetached(allocator, message, signature_msg);
}

/// Verify a detached signature with caller-specified options.
/// Use `opts.trusted_signers` to restrict accepted signing keys and
/// `opts.version_policy` to restrict accepted protocol versions.
pub fn verifyDetachedWithOptions(
    allocator: Allocator,
    message: []const u8,
    signature_msg: []const u8,
    opts: VerifyOptions,
) !VerifyDetachedResult {
    return verify.verifyDetachedWithOptions(allocator, message, signature_msg, opts);
}

// ---------------------------------------------------------------------------
// Signcryption convenience API
// ---------------------------------------------------------------------------

/// Signcrypt a plaintext message (encrypt + sign in one operation, v2 only).
pub fn signcryptSeal(
    allocator: Allocator,
    plaintext: []const u8,
    sender_signing_key: ?SigningSecretKey,
    opts: SigncryptSealOptions,
) ![]u8 {
    return signcrypt.seal(allocator, plaintext, sender_signing_key, opts);
}

/// Open a signcrypted message.
///
/// WARNING: This convenience function uses a universal signing key lookup
/// that accepts ANY sender. It does NOT authenticate the sender's identity.
/// After decryption, callers MUST inspect `result.key_info.sender_key` to
/// verify that the sender is who they expect. If `sender_is_anonymous` is
/// true, the sender chose to remain anonymous and cannot be verified.
/// For custom signing key lookup behavior (e.g. restricting to a set of
/// trusted senders), call `signcrypt.open()` directly with a custom lookup
/// function.
///
/// **Security warning:** On failure this function returns specific error codes
/// (e.g. `NoDecryptionKey`, `DecryptionFailed`, `NoSenderKey`) that reveal
/// how far processing progressed. When used in a server or API context, use
/// `toSafeError()` to collapse these into a generic `SafeError` before
/// returning them to untrusted parties.
pub fn signcryptOpen(
    allocator: Allocator,
    ciphertext: []const u8,
    keyring: []const BoxKeyPair,
) !SigncryptOpenResult {
    return signcryptOpenWithOptions(allocator, ciphertext, keyring, .{});
}

/// Open a signcrypted message with additional options (e.g. symmetric keys).
///
/// WARNING: This convenience function uses a universal signing key lookup
/// that accepts ANY sender. It does NOT authenticate the sender's identity.
/// After decryption, callers MUST inspect `result.key_info.sender_key` to
/// verify that the sender is who they expect. For custom signing key lookup
/// behavior, call `signcrypt.open()` directly.
pub fn signcryptOpenWithOptions(
    allocator: Allocator,
    ciphertext: []const u8,
    keyring: []const BoxKeyPair,
    open_opts: SigncryptOpenOptions,
) !SigncryptOpenResult {
    const lookup = struct {
        fn lookupFn(pk_bytes: [32]u8) ?SigningPublicKey {
            return SigningPublicKey.fromBytes(pk_bytes) catch return null;
        }
    };
    return signcrypt.open(allocator, ciphertext, keyring, &lookup.lookupFn, open_opts);
}

// ---------------------------------------------------------------------------
// Signer-identity verification wrappers
// ---------------------------------------------------------------------------

/// Verify an attached signature and assert that it was produced by a specific signer.
///
/// This is a convenience wrapper around `verifyAttached` that eliminates a
/// common misuse pattern: calling `verifyAttached`, receiving the signer
/// public key in the result, but never actually checking it -- thereby
/// silently accepting messages signed by *any* key.
///
/// Use this function when you know exactly which signing key to expect.
/// If you need to accept messages from a *set* of trusted signers, use
/// `verifyAttachedWithOptions` with the `trusted_signers` field instead.
///
/// Returns `error.UnexpectedSigner` if the message was signed by a key
/// other than `expected_signer`.
pub fn verifyAttachedFrom(
    allocator: Allocator,
    signed_msg: []const u8,
    expected_signer: SigningPublicKey,
) !VerifyResult {
    const result = try verifyAttached(allocator, signed_msg);
    errdefer result.deinit();
    if (!result.signer.eql(expected_signer)) {
        return Error.UnexpectedSigner;
    }
    return result;
}

/// Verify a detached signature and assert that it was produced by a specific signer.
///
/// This is a convenience wrapper around `verifyDetached` that eliminates a
/// common misuse pattern: calling `verifyDetached`, receiving the signer
/// public key in the result, but never actually checking it -- thereby
/// silently accepting signatures from *any* key.
///
/// Use this function when you know exactly which signing key to expect.
/// If you need to accept signatures from a *set* of trusted signers, use
/// `verifyDetachedWithOptions` with the `trusted_signers` field instead.
///
/// Returns `error.UnexpectedSigner` if the signature was produced by a key
/// other than `expected_signer`.
pub fn verifyDetachedFrom(
    allocator: Allocator,
    message: []const u8,
    signature_msg: []const u8,
    expected_signer: SigningPublicKey,
) !VerifyDetachedResult {
    const result = try verifyDetached(allocator, message, signature_msg);
    if (!result.signer.eql(expected_signer)) {
        return Error.UnexpectedSigner;
    }
    return result;
}

/// Open a signcrypted message and assert that it was sent by a specific signer.
///
/// This is a convenience wrapper around `signcryptOpen` that eliminates a
/// common misuse pattern: calling `signcryptOpen`, receiving the sender
/// information in `result.key_info`, but never actually checking it --
/// thereby silently accepting messages from *any* sender (including
/// anonymous ones).
///
/// Use this function when you know exactly which signing key to expect.
/// If the sender chose to remain anonymous (`sender_is_anonymous` is true)
/// but `expected_signer` is non-null, this returns `error.UnexpectedSigner`
/// because the sender's identity cannot be verified.
///
/// Returns `error.UnexpectedSigner` if:
///   - The sender is anonymous (identity cannot be verified), or
///   - The sender's signing key does not match `expected_signer`.
pub fn signcryptOpenFrom(
    allocator: Allocator,
    ciphertext: []const u8,
    keyring: []const BoxKeyPair,
    expected_signer: SigningPublicKey,
) !SigncryptOpenResult {
    const result = try signcryptOpen(allocator, ciphertext, keyring);
    errdefer result.deinit();
    if (result.key_info.sender_is_anonymous) {
        return Error.UnexpectedSigner;
    }
    if (result.key_info.sender_key) |actual_sender_bytes| {
        if (!std.crypto.timing_safe.eql([32]u8, actual_sender_bytes, expected_signer.bytes)) {
            return Error.UnexpectedSigner;
        }
    } else {
        return Error.UnexpectedSigner;
    }
    return result;
}

// ---------------------------------------------------------------------------
// Armored convenience API
// ---------------------------------------------------------------------------

/// Encrypt and armor a plaintext message.
/// Returns the armored string (caller must free).
pub fn armorSeal(
    allocator: Allocator,
    plaintext: []const u8,
    sender: ?BoxSecretKey,
    receivers: []const BoxPublicKey,
    opts: SealOptions,
    brand: ?[]const u8,
) ![]u8 {
    const ct = try encrypt.seal(allocator, plaintext, sender, receivers, opts);
    defer allocator.free(ct);
    return armor.encode(allocator, ct, .encryption, brand);
}

/// Dearmor and decrypt a message.
/// Returns the decrypted plaintext and key metadata.
pub fn armorOpen(
    allocator: Allocator,
    armored_msg: []const u8,
    keyring: []const BoxKeyPair,
) !OpenResult {
    const decoded = try armor.decode(allocator, armored_msg);
    defer allocator.free(decoded.data);
    if (decoded.frame.message_type != .encryption) return Error.WrongMessageType;
    return decrypt.open(allocator, decoded.data, keyring, .{});
}

/// Dearmor and decrypt a message with caller-specified options.
/// Use `opts.version_policy` to restrict which protocol versions are accepted.
pub fn armorOpenWithOptions(
    allocator: Allocator,
    armored_msg: []const u8,
    keyring: []const BoxKeyPair,
    opts: OpenOptions,
) !OpenResult {
    const decoded = try armor.decode(allocator, armored_msg);
    defer allocator.free(decoded.data);
    if (decoded.frame.message_type != .encryption) return Error.WrongMessageType;
    return decrypt.open(allocator, decoded.data, keyring, opts);
}

/// Sign (attached) and armor a plaintext message.
pub fn armorSignAttached(
    allocator: Allocator,
    plaintext: []const u8,
    signer: SigningSecretKey,
    opts: SignOptions,
    brand: ?[]const u8,
) ![]u8 {
    const signed = try sign.sign(allocator, plaintext, signer, opts);
    defer signed.deinit();
    return armor.encode(allocator, signed.data, .attached_signature, brand);
}

/// Dearmor and verify an attached signature message.
pub fn armorVerifyAttached(
    allocator: Allocator,
    armored_msg: []const u8,
) !VerifyResult {
    const decoded = try armor.decode(allocator, armored_msg);
    defer allocator.free(decoded.data);
    if (decoded.frame.message_type != .attached_signature) return Error.WrongMessageType;
    return verify.verify(allocator, decoded.data);
}

/// Dearmor and verify an attached signature message with caller-specified options.
pub fn armorVerifyAttachedWithOptions(
    allocator: Allocator,
    armored_msg: []const u8,
    opts: VerifyOptions,
) !VerifyResult {
    const decoded = try armor.decode(allocator, armored_msg);
    defer allocator.free(decoded.data);
    if (decoded.frame.message_type != .attached_signature) return Error.WrongMessageType;
    return verify.verifyWithOptions(allocator, decoded.data, opts);
}

/// Sign (detached) and armor the signature.
pub fn armorSignDetached(
    allocator: Allocator,
    plaintext: []const u8,
    signer: SigningSecretKey,
    opts: SignOptions,
    brand: ?[]const u8,
) ![]u8 {
    const sig = try sign.signDetached(allocator, plaintext, signer, opts);
    defer sig.deinit();
    return armor.encode(allocator, sig.data, .detached_signature, brand);
}

/// Dearmor a detached signature and verify it against the message.
pub fn armorVerifyDetached(
    allocator: Allocator,
    message: []const u8,
    armored_sig: []const u8,
) !VerifyDetachedResult {
    const decoded = try armor.decode(allocator, armored_sig);
    defer allocator.free(decoded.data);
    if (decoded.frame.message_type != .detached_signature) return Error.WrongMessageType;
    return verify.verifyDetached(allocator, message, decoded.data);
}

/// Dearmor a detached signature and verify it with caller-specified options.
pub fn armorVerifyDetachedWithOptions(
    allocator: Allocator,
    message: []const u8,
    armored_sig: []const u8,
    opts: VerifyOptions,
) !VerifyDetachedResult {
    const decoded = try armor.decode(allocator, armored_sig);
    defer allocator.free(decoded.data);
    if (decoded.frame.message_type != .detached_signature) return Error.WrongMessageType;
    return verify.verifyDetachedWithOptions(allocator, message, decoded.data, opts);
}

// ---------------------------------------------------------------------------
// Tests — pull in submodule tests (modules are internal, so refAllDecls
// would not discover them; we import them explicitly here).
// ---------------------------------------------------------------------------

test {
    std.testing.refAllDecls(@This());

    // Ensure tests in internal submodules are still discovered by the
    // test runner even though the modules are no longer pub.
    _ = basex;
    _ = types;
    _ = errors;
    _ = key;
    _ = nonce;
    _ = header;
    _ = armor;
    _ = encrypt;
    _ = decrypt;
    _ = sign;
    _ = verify;
    _ = signcrypt;
    _ = stream;
    _ = @import("test_vectors.zig");
    _ = @import("fuzz.zig");
}

// ---------------------------------------------------------------------------
// Integration tests
// ---------------------------------------------------------------------------

test "integration: encrypt V2 → decrypt round-trip" {
    const allocator = std.testing.allocator;
    const sender_kp = BoxKeyPair.generate();
    const receiver_kp = BoxKeyPair.generate();

    const msg = "end-to-end encryption test";
    const receiver_pks = [_]BoxPublicKey{receiver_kp.public_key};
    const ct = try seal(allocator, msg, sender_kp.secret_key, &receiver_pks, .{});
    defer allocator.free(ct);

    const keyring = [_]BoxKeyPair{receiver_kp};
    const result = try open(allocator, ct, &keyring);
    defer result.deinit();

    try std.testing.expectEqualStrings(msg, result.plaintext);
    try std.testing.expect(!result.key_info.sender_is_anonymous);
    try std.testing.expectEqualSlices(u8, &sender_kp.public_key.bytes, &result.key_info.sender_key.?);
}

test "integration: encrypt V1 → decrypt round-trip" {
    const allocator = std.testing.allocator;
    const sender_kp = BoxKeyPair.generate();
    const receiver_kp = BoxKeyPair.generate();

    const msg = "v1 encryption integration test";
    const receiver_pks = [_]BoxPublicKey{receiver_kp.public_key};
    const ct = try seal(allocator, msg, sender_kp.secret_key, &receiver_pks, .{
        .version = Version.v1(),
    });
    defer allocator.free(ct);

    const keyring = [_]BoxKeyPair{receiver_kp};
    const result = try open(allocator, ct, &keyring);
    defer result.deinit();

    try std.testing.expectEqualStrings(msg, result.plaintext);
}

test "integration: sign attached → verify round-trip" {
    const allocator = std.testing.allocator;
    const signer = SigningKeyPair.generate();

    const msg = "end-to-end signing test";
    const signed = try signAttached(allocator, msg, signer.secret_key, .{});
    defer signed.deinit();

    const result = try verifyAttached(allocator, signed.data);
    defer result.deinit();

    try std.testing.expectEqualStrings(msg, result.plaintext);
    try std.testing.expect(result.signer.eql(signer.public_key));
}

test "integration: sign detached → verify round-trip" {
    const allocator = std.testing.allocator;
    const signer = SigningKeyPair.generate();

    const msg = "detached signing integration test";
    const sig = try signDetached(allocator, msg, signer.secret_key, .{});
    defer sig.deinit();

    const result = try verifyDetached(allocator, msg, sig.data);
    try std.testing.expect(result.signer.eql(signer.public_key));
}

test "integration: signcrypt → open round-trip" {
    const allocator = std.testing.allocator;
    const signing_kp = SigningKeyPair.generate();
    const box_kp = BoxKeyPair.generate();

    const msg = "signcrypt integration test";
    const receiver_box_keys = [_]BoxPublicKey{box_kp.public_key};
    const ct = try signcryptSeal(allocator, msg, signing_kp.secret_key, .{
        .receiver_box_keys = &receiver_box_keys,
    });
    defer allocator.free(ct);

    const keyring = [_]BoxKeyPair{box_kp};

    const result = try signcryptOpen(allocator, ct, &keyring);
    defer result.deinit();

    try std.testing.expectEqualStrings(msg, result.plaintext);
    try std.testing.expect(!result.key_info.sender_is_anonymous);
}

test "integration: armored encrypt → armored decrypt" {
    const allocator = std.testing.allocator;
    const sender_kp = BoxKeyPair.generate();
    const receiver_kp = BoxKeyPair.generate();

    const msg = "armored encryption integration test";
    const receiver_pks = [_]BoxPublicKey{receiver_kp.public_key};
    const armored_ct = try armorSeal(allocator, msg, sender_kp.secret_key, &receiver_pks, .{}, null);
    defer allocator.free(armored_ct);

    // Verify it looks like an armored message.
    try std.testing.expect(std.mem.startsWith(u8, armored_ct, "BEGIN SALTPACK ENCRYPTED MESSAGE."));

    const keyring = [_]BoxKeyPair{receiver_kp};
    const result = try armorOpen(allocator, armored_ct, &keyring);
    defer result.deinit();

    try std.testing.expectEqualStrings(msg, result.plaintext);
}

test "integration: armored encrypt with brand" {
    const allocator = std.testing.allocator;
    const sender_kp = BoxKeyPair.generate();
    const receiver_kp = BoxKeyPair.generate();

    const msg = "branded encryption";
    const receiver_pks = [_]BoxPublicKey{receiver_kp.public_key};
    const armored_ct = try armorSeal(allocator, msg, sender_kp.secret_key, &receiver_pks, .{}, "MYAPP");
    defer allocator.free(armored_ct);

    try std.testing.expect(std.mem.startsWith(u8, armored_ct, "BEGIN MYAPP SALTPACK ENCRYPTED MESSAGE."));

    const keyring = [_]BoxKeyPair{receiver_kp};
    const result = try armorOpen(allocator, armored_ct, &keyring);
    defer result.deinit();

    try std.testing.expectEqualStrings(msg, result.plaintext);
}

test "integration: armored sign attached → verify" {
    const allocator = std.testing.allocator;
    const signer = SigningKeyPair.generate();

    const msg = "armored signed message";
    const armored_sig = try armorSignAttached(allocator, msg, signer.secret_key, .{}, null);
    defer allocator.free(armored_sig);

    try std.testing.expect(std.mem.startsWith(u8, armored_sig, "BEGIN SALTPACK SIGNED MESSAGE."));

    const result = try armorVerifyAttached(allocator, armored_sig);
    defer result.deinit();

    try std.testing.expectEqualStrings(msg, result.plaintext);
    try std.testing.expect(result.signer.eql(signer.public_key));
}

test "integration: armored sign detached → verify" {
    const allocator = std.testing.allocator;
    const signer = SigningKeyPair.generate();

    const msg = "armored detached signature test";
    const armored_sig = try armorSignDetached(allocator, msg, signer.secret_key, .{}, null);
    defer allocator.free(armored_sig);

    try std.testing.expect(std.mem.startsWith(u8, armored_sig, "BEGIN SALTPACK DETACHED SIGNATURE."));

    const result = try armorVerifyDetached(allocator, msg, armored_sig);
    try std.testing.expect(result.signer.eql(signer.public_key));
}

test "integration: anonymous sender encrypt → decrypt" {
    const allocator = std.testing.allocator;
    const receiver_kp = BoxKeyPair.generate();

    const msg = "anonymous sender integration";
    const receiver_pks = [_]BoxPublicKey{receiver_kp.public_key};
    const ct = try seal(allocator, msg, null, &receiver_pks, .{});
    defer allocator.free(ct);

    const keyring = [_]BoxKeyPair{receiver_kp};
    const result = try open(allocator, ct, &keyring);
    defer result.deinit();

    try std.testing.expectEqualStrings(msg, result.plaintext);
    try std.testing.expect(result.key_info.sender_is_anonymous);
    try std.testing.expect(result.key_info.sender_key == null);
}

test "integration: multi-receiver encrypt → each can decrypt" {
    const allocator = std.testing.allocator;
    const sender_kp = BoxKeyPair.generate();
    const r1 = BoxKeyPair.generate();
    const r2 = BoxKeyPair.generate();

    const msg = "multi-receiver integration";
    const receiver_pks = [_]BoxPublicKey{ r1.public_key, r2.public_key };
    const ct = try seal(allocator, msg, sender_kp.secret_key, &receiver_pks, .{});
    defer allocator.free(ct);

    // Receiver 1
    {
        const keyring = [_]BoxKeyPair{r1};
        const result = try open(allocator, ct, &keyring);
        defer result.deinit();
        try std.testing.expectEqualStrings(msg, result.plaintext);
    }

    // Receiver 2
    {
        const keyring = [_]BoxKeyPair{r2};
        const result = try open(allocator, ct, &keyring);
        defer result.deinit();
        try std.testing.expectEqualStrings(msg, result.plaintext);
    }
}

test "cross-protocol: decrypt rejects signed message" {
    const allocator = std.testing.allocator;
    const signer = SigningKeyPair.generate();
    const receiver_kp = BoxKeyPair.generate();

    // Create a signed (attached) message.
    const msg = "signed not encrypted";
    const signed = try signAttached(allocator, msg, signer.secret_key, .{});
    defer signed.deinit();

    // Try to decrypt the signed message -- should fail with WrongMessageType.
    const keyring = [_]BoxKeyPair{receiver_kp};
    const result = open(allocator, signed.data, &keyring);
    try std.testing.expectError(Error.WrongMessageType, result);
}

test "cross-protocol: verify rejects encrypted message" {
    const allocator = std.testing.allocator;
    const sender_kp = BoxKeyPair.generate();
    const receiver_kp = BoxKeyPair.generate();

    // Create an encrypted message.
    const msg = "encrypted not signed";
    const receiver_pks = [_]BoxPublicKey{receiver_kp.public_key};
    const ct = try seal(allocator, msg, sender_kp.secret_key, &receiver_pks, .{});
    defer allocator.free(ct);

    // Try to verify the encrypted message -- should fail with WrongMessageType.
    const result = verifyAttached(allocator, ct);
    try std.testing.expectError(Error.WrongMessageType, result);
}

test "cross-protocol: signcrypt open rejects encrypted message" {
    const allocator = std.testing.allocator;
    const sender_kp = BoxKeyPair.generate();
    const receiver_kp = BoxKeyPair.generate();

    // Create a regular encrypted message.
    const msg = "encrypted not signcrypted";
    const receiver_pks = [_]BoxPublicKey{receiver_kp.public_key};
    const ct = try seal(allocator, msg, sender_kp.secret_key, &receiver_pks, .{});
    defer allocator.free(ct);

    // Try to open via signcrypt -- should fail with WrongMessageType.
    const keyring = [_]BoxKeyPair{receiver_kp};

    const result = signcryptOpen(allocator, ct, &keyring);
    try std.testing.expectError(Error.WrongMessageType, result);
}

// ---------------------------------------------------------------------------
// WithOptions convenience wrapper tests
// ---------------------------------------------------------------------------

test "verifyAttachedWithOptions accepts trusted signer" {
    const allocator = std.testing.allocator;
    const kp = SigningKeyPair.generate();
    const msg = "attached with options trusted";

    const signed = try signAttached(allocator, msg, kp.secret_key, .{});
    defer signed.deinit();

    const trusted = [_]SigningPublicKey{kp.public_key};
    const result = try verifyAttachedWithOptions(allocator, signed.data, .{
        .trusted_signers = &trusted,
    });
    defer result.deinit();

    try std.testing.expectEqualStrings(msg, result.plaintext);
    try std.testing.expect(result.signer.eql(kp.public_key));
}

test "verifyAttachedWithOptions rejects untrusted signer" {
    const allocator = std.testing.allocator;
    const kp_signer = SigningKeyPair.generate();
    const kp_other = SigningKeyPair.generate();
    const msg = "attached with options untrusted";

    const signed = try signAttached(allocator, msg, kp_signer.secret_key, .{});
    defer signed.deinit();

    const trusted = [_]SigningPublicKey{kp_other.public_key};
    const result = verifyAttachedWithOptions(allocator, signed.data, .{
        .trusted_signers = &trusted,
    });
    try std.testing.expectError(Error.UntrustedSigner, result);
}

test "verifyAttachedWithOptions enforces version policy" {
    const allocator = std.testing.allocator;
    const kp = SigningKeyPair.generate();
    const msg = "attached version policy test";

    // Sign with V2.
    const signed = try signAttached(allocator, msg, kp.secret_key, .{});
    defer signed.deinit();

    // Accept V2 -- should succeed.
    const r1 = try verifyAttachedWithOptions(allocator, signed.data, .{
        .version_policy = VersionPolicy.v2Only(),
    });
    defer r1.deinit();
    try std.testing.expectEqualStrings(msg, r1.plaintext);

    // Reject V2 (only allow V1) -- should fail.
    const r2 = verifyAttachedWithOptions(allocator, signed.data, .{
        .version_policy = VersionPolicy.v1Only(),
    });
    try std.testing.expectError(Error.VersionNotAllowed, r2);
}

test "verifyDetachedWithOptions accepts trusted signer" {
    const allocator = std.testing.allocator;
    const kp = SigningKeyPair.generate();
    const msg = "detached with options trusted";

    const sig = try signDetached(allocator, msg, kp.secret_key, .{});
    defer sig.deinit();

    const trusted = [_]SigningPublicKey{kp.public_key};
    const result = try verifyDetachedWithOptions(allocator, msg, sig.data, .{
        .trusted_signers = &trusted,
    });

    try std.testing.expect(result.signer.eql(kp.public_key));
}

test "verifyDetachedWithOptions rejects untrusted signer" {
    const allocator = std.testing.allocator;
    const kp_signer = SigningKeyPair.generate();
    const kp_other = SigningKeyPair.generate();
    const msg = "detached with options untrusted";

    const sig = try signDetached(allocator, msg, kp_signer.secret_key, .{});
    defer sig.deinit();

    const trusted = [_]SigningPublicKey{kp_other.public_key};
    const result = verifyDetachedWithOptions(allocator, msg, sig.data, .{
        .trusted_signers = &trusted,
    });
    try std.testing.expectError(Error.UntrustedSigner, result);
}

test "verifyDetachedWithOptions enforces version policy" {
    const allocator = std.testing.allocator;
    const kp = SigningKeyPair.generate();
    const msg = "detached version policy test";

    // Sign with V2.
    const sig = try signDetached(allocator, msg, kp.secret_key, .{});
    defer sig.deinit();

    // Accept V2 -- should succeed.
    const r1 = try verifyDetachedWithOptions(allocator, msg, sig.data, .{
        .version_policy = VersionPolicy.v2Only(),
    });
    try std.testing.expect(r1.signer.eql(kp.public_key));

    // Reject V2 (only allow V1) -- should fail.
    const r2 = verifyDetachedWithOptions(allocator, msg, sig.data, .{
        .version_policy = VersionPolicy.v1Only(),
    });
    try std.testing.expectError(Error.VersionNotAllowed, r2);
}

test "armorVerifyAttachedWithOptions accepts trusted signer" {
    const allocator = std.testing.allocator;
    const kp = SigningKeyPair.generate();
    const msg = "armored attached with options";

    const armored_sig = try armorSignAttached(allocator, msg, kp.secret_key, .{}, null);
    defer allocator.free(armored_sig);

    const trusted = [_]SigningPublicKey{kp.public_key};
    const result = try armorVerifyAttachedWithOptions(allocator, armored_sig, .{
        .trusted_signers = &trusted,
    });
    defer result.deinit();

    try std.testing.expectEqualStrings(msg, result.plaintext);
    try std.testing.expect(result.signer.eql(kp.public_key));
}

test "armorVerifyAttachedWithOptions rejects untrusted signer" {
    const allocator = std.testing.allocator;
    const kp_signer = SigningKeyPair.generate();
    const kp_other = SigningKeyPair.generate();
    const msg = "armored attached untrusted";

    const armored_sig = try armorSignAttached(allocator, msg, kp_signer.secret_key, .{}, null);
    defer allocator.free(armored_sig);

    const trusted = [_]SigningPublicKey{kp_other.public_key};
    const result = armorVerifyAttachedWithOptions(allocator, armored_sig, .{
        .trusted_signers = &trusted,
    });
    try std.testing.expectError(Error.UntrustedSigner, result);
}

test "armorVerifyDetachedWithOptions accepts trusted signer" {
    const allocator = std.testing.allocator;
    const kp = SigningKeyPair.generate();
    const msg = "armored detached with options";

    const armored_sig = try armorSignDetached(allocator, msg, kp.secret_key, .{}, null);
    defer allocator.free(armored_sig);

    const trusted = [_]SigningPublicKey{kp.public_key};
    const result = try armorVerifyDetachedWithOptions(allocator, msg, armored_sig, .{
        .trusted_signers = &trusted,
    });

    try std.testing.expect(result.signer.eql(kp.public_key));
}

test "armorVerifyDetachedWithOptions rejects untrusted signer" {
    const allocator = std.testing.allocator;
    const kp_signer = SigningKeyPair.generate();
    const kp_other = SigningKeyPair.generate();
    const msg = "armored detached untrusted";

    const armored_sig = try armorSignDetached(allocator, msg, kp_signer.secret_key, .{}, null);
    defer allocator.free(armored_sig);

    const trusted = [_]SigningPublicKey{kp_other.public_key};
    const result = armorVerifyDetachedWithOptions(allocator, msg, armored_sig, .{
        .trusted_signers = &trusted,
    });
    try std.testing.expectError(Error.UntrustedSigner, result);
}

test "VerifyDetachedResult deinit is callable" {
    const allocator = std.testing.allocator;
    const kp = SigningKeyPair.generate();
    const msg = "deinit consistency test";

    const sig = try signDetached(allocator, msg, kp.secret_key, .{});
    defer sig.deinit();

    const result = try verifyDetached(allocator, msg, sig.data);
    // Call deinit for API consistency -- it's a no-op but should compile and not crash.
    defer result.deinit();

    try std.testing.expect(result.signer.eql(kp.public_key));
}

test "signcryptOpenWithOptions with symmetric keys via public API" {
    const allocator = std.testing.allocator;

    const msg = "signcryptOpenWithOptions symmetric test";
    const sym_key: [32]u8 = [_]u8{0xAA} ** 32;
    const identifier = [_]u8{0xBB} ** 32;

    const sym_rcvs = [_]ReceiverSymmetricKey{
        .{ .symmetric_key = sym_key, .identifier = &identifier },
    };

    // Seal with anonymous sender and symmetric key recipient via public API.
    const ct = try signcryptSeal(allocator, msg, null, .{
        .receiver_symmetric_keys = &sym_rcvs,
    });
    defer allocator.free(ct);

    // Open via signcryptOpenWithOptions using the symmetric key.
    const empty_keyring = [_]BoxKeyPair{};
    const result = try signcryptOpenWithOptions(allocator, ct, &empty_keyring, .{
        .receiver_symmetric_keys = &sym_rcvs,
    });
    defer result.deinit();

    try std.testing.expectEqualStrings(msg, result.plaintext);
    try std.testing.expect(result.key_info.sender_is_anonymous);
}

// ---------------------------------------------------------------------------
// toSafeError tests
// ---------------------------------------------------------------------------

test "toSafeError maps decryption errors to decryption_failed" {
    const decryption_errors = [_]anyerror{
        error.NoDecryptionKey,
        error.BadSenderKeySecretbox,
        error.DecryptionFailed,
        error.BadCiphertext,
        error.NoSenderKey,
    };
    for (decryption_errors) |err| {
        try std.testing.expectEqual(SafeError.decryption_failed, toSafeError(err));
    }
}

test "toSafeError maps verification errors to verification_failed" {
    const verification_errors = [_]anyerror{
        error.BadSignature,
        error.UntrustedSigner,
    };
    for (verification_errors) |err| {
        try std.testing.expectEqual(SafeError.verification_failed, toSafeError(err));
    }
}

test "toSafeError maps input validation errors to invalid_input" {
    const input_errors = [_]anyerror{
        error.BadVersion,
        error.WrongMessageType,
        error.BadFrame,
        error.NotASaltpackMessage,
        error.BadEphemeralKey,
        error.TrailingGarbage,
        error.PacketOverflow,
        error.UnexpectedEmptyBlock,
        error.FailedToReadHeaderBytes,
        error.BadBoxKey,
        error.TruncatedMessage,
        error.TooManyReceivers,
        error.BadReceivers,
        error.RepeatedKey,
        error.VersionNotAllowed,
        error.BadPublicKey,
        error.BadSecretKey,
    };
    for (input_errors) |err| {
        try std.testing.expectEqual(SafeError.invalid_input, toSafeError(err));
    }
}

test "toSafeError maps armor errors to invalid_input" {
    const armor_errors = [_]anyerror{
        armor.Error.BadFrame,
        armor.Error.FrameMismatch,
        armor.Error.Truncated,
    };
    for (armor_errors) |err| {
        try std.testing.expectEqual(SafeError.invalid_input, toSafeError(err));
    }
}

test "toSafeError maps unknown errors to internal_error" {
    try std.testing.expectEqual(SafeError.internal_error, toSafeError(error.OutOfMemory));
    try std.testing.expectEqual(SafeError.internal_error, toSafeError(error.Unexpected));
}

test "toSafeError collapses distinct decryption errors into same category" {
    // Verifies that an attacker cannot distinguish between these two common
    // decryption failures when the caller uses toSafeError.
    const no_key = toSafeError(error.NoDecryptionKey);
    const bad_ct = toSafeError(error.DecryptionFailed);
    try std.testing.expectEqual(no_key, bad_ct);
}

test "toSafeError practical usage with open()" {
    const allocator = std.testing.allocator;
    const sender_kp = BoxKeyPair.generate();
    const receiver_kp = BoxKeyPair.generate();
    const wrong_kp = BoxKeyPair.generate();

    const msg = "safe error practical test";
    const receiver_pks = [_]BoxPublicKey{receiver_kp.public_key};
    const ct = try seal(allocator, msg, sender_kp.secret_key, &receiver_pks, .{});
    defer allocator.free(ct);

    // Try to decrypt with the wrong key -- internally this is NoDecryptionKey,
    // but toSafeError should map it to the generic decryption_failed.
    const keyring = [_]BoxKeyPair{wrong_kp};
    _ = open(allocator, ct, &keyring) catch |err| {
        const safe = toSafeError(err);
        try std.testing.expectEqual(SafeError.decryption_failed, safe);
        return;
    };
    // Should not reach here -- decryption should fail.
    return error.TestUnexpectedResult;
}

test "toSafeError practical usage with verifyAttached()" {
    const allocator = std.testing.allocator;
    const kp = SigningKeyPair.generate();
    const msg = "safe error verify test";

    const signed = try signAttached(allocator, msg, kp.secret_key, .{});
    defer signed.deinit();

    // Tamper with the signed message.
    const tampered = try allocator.alloc(u8, signed.data.len);
    defer allocator.free(tampered);
    @memcpy(tampered, signed.data);
    tampered[tampered.len - 1] ^= 0xFF;

    _ = verifyAttached(allocator, tampered) catch |err| {
        const safe = toSafeError(err);
        try std.testing.expectEqual(SafeError.verification_failed, safe);
        return;
    };
    return error.TestUnexpectedResult;
}

// ---------------------------------------------------------------------------
// verifyAttachedFrom / verifyDetachedFrom / signcryptOpenFrom tests
// ---------------------------------------------------------------------------

test "verifyAttachedFrom accepts correct signer" {
    const allocator = std.testing.allocator;
    const kp = SigningKeyPair.generate();
    const msg = "verifyAttachedFrom correct signer";

    const signed = try signAttached(allocator, msg, kp.secret_key, .{});
    defer signed.deinit();

    const result = try verifyAttachedFrom(allocator, signed.data, kp.public_key);
    defer result.deinit();

    try std.testing.expectEqualStrings(msg, result.plaintext);
    try std.testing.expect(result.signer.eql(kp.public_key));
}

test "verifyAttachedFrom rejects wrong signer" {
    const allocator = std.testing.allocator;
    const kp_signer = SigningKeyPair.generate();
    const kp_other = SigningKeyPair.generate();
    const msg = "verifyAttachedFrom wrong signer";

    const signed = try signAttached(allocator, msg, kp_signer.secret_key, .{});
    defer signed.deinit();

    const result = verifyAttachedFrom(allocator, signed.data, kp_other.public_key);
    try std.testing.expectError(Error.UnexpectedSigner, result);
}

test "verifyDetachedFrom accepts correct signer" {
    const allocator = std.testing.allocator;
    const kp = SigningKeyPair.generate();
    const msg = "verifyDetachedFrom correct signer";

    const sig = try signDetached(allocator, msg, kp.secret_key, .{});
    defer sig.deinit();

    const result = try verifyDetachedFrom(allocator, msg, sig.data, kp.public_key);
    try std.testing.expect(result.signer.eql(kp.public_key));
}

test "verifyDetachedFrom rejects wrong signer" {
    const allocator = std.testing.allocator;
    const kp_signer = SigningKeyPair.generate();
    const kp_other = SigningKeyPair.generate();
    const msg = "verifyDetachedFrom wrong signer";

    const sig = try signDetached(allocator, msg, kp_signer.secret_key, .{});
    defer sig.deinit();

    const result = verifyDetachedFrom(allocator, msg, sig.data, kp_other.public_key);
    try std.testing.expectError(Error.UnexpectedSigner, result);
}

test "signcryptOpenFrom accepts correct signer" {
    const allocator = std.testing.allocator;
    const signing_kp = SigningKeyPair.generate();
    const box_kp = BoxKeyPair.generate();

    const msg = "signcryptOpenFrom correct signer";
    const receiver_box_keys = [_]BoxPublicKey{box_kp.public_key};
    const ct = try signcryptSeal(allocator, msg, signing_kp.secret_key, .{
        .receiver_box_keys = &receiver_box_keys,
    });
    defer allocator.free(ct);

    const keyring = [_]BoxKeyPair{box_kp};
    const result = try signcryptOpenFrom(allocator, ct, &keyring, signing_kp.public_key);
    defer result.deinit();

    try std.testing.expectEqualStrings(msg, result.plaintext);
    try std.testing.expect(!result.key_info.sender_is_anonymous);
}

test "signcryptOpenFrom rejects wrong signer" {
    const allocator = std.testing.allocator;
    const signing_kp = SigningKeyPair.generate();
    const wrong_kp = SigningKeyPair.generate();
    const box_kp = BoxKeyPair.generate();

    const msg = "signcryptOpenFrom wrong signer";
    const receiver_box_keys = [_]BoxPublicKey{box_kp.public_key};
    const ct = try signcryptSeal(allocator, msg, signing_kp.secret_key, .{
        .receiver_box_keys = &receiver_box_keys,
    });
    defer allocator.free(ct);

    const keyring = [_]BoxKeyPair{box_kp};
    const result = signcryptOpenFrom(allocator, ct, &keyring, wrong_kp.public_key);
    try std.testing.expectError(Error.UnexpectedSigner, result);
}

test "signcryptOpenFrom rejects anonymous sender" {
    const allocator = std.testing.allocator;
    const box_kp = BoxKeyPair.generate();
    const expected_kp = SigningKeyPair.generate();

    const msg = "signcryptOpenFrom anonymous sender";
    const receiver_box_keys = [_]BoxPublicKey{box_kp.public_key};
    // Seal with null signing key (anonymous sender).
    const ct = try signcryptSeal(allocator, msg, null, .{
        .receiver_box_keys = &receiver_box_keys,
    });
    defer allocator.free(ct);

    const keyring = [_]BoxKeyPair{box_kp};
    // Expecting a specific signer but the sender is anonymous -- should fail.
    const result = signcryptOpenFrom(allocator, ct, &keyring, expected_kp.public_key);
    try std.testing.expectError(Error.UnexpectedSigner, result);
}
