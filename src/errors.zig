//! Error types for saltpack operations.
//!
//! Zig port of the Go saltpack library's errors.go.

const std = @import("std");

// ---------------------------------------------------------------------------
// Error set
// ---------------------------------------------------------------------------

/// Comprehensive error set for all saltpack operations.
/// Each variant corresponds to an error defined in the Go reference implementation.
pub const Error = error{
    /// An unsupported version was encountered in the message.
    BadVersion,

    /// The message type did not match what was expected.
    WrongMessageType,

    /// An error occurred in the BEGIN or END framing of the outer message
    /// structure. Note: armor-specific framing errors use `armor.Error.BadFrame`.
    BadFrame,

    /// The input is not a valid saltpack message.
    NotASaltpackMessage,

    /// Decryption of a ciphertext block failed (bad Poly1305 authentication).
    BadCiphertext,

    /// No decryption key was found for the incoming message.
    NoDecryptionKey,

    /// The sender secretbox failed to open.
    BadSenderKeySecretbox,

    /// A generic decryption operation failed.
    DecryptionFailed,

    /// Signature verification failed.
    BadSignature,

    /// No sender key was found for the message.
    NoSenderKey,

    /// A recipient key was repeated; keys must be unique.
    RepeatedKey,

    /// A bad receivers argument was provided.
    BadReceivers,

    /// An ephemeral key failed to be properly imported.
    BadEphemeralKey,

    /// Trailing data was found after the end of the message stream.
    TrailingGarbage,

    /// More than 2^32 packets were found in a message.
    PacketOverflow,

    /// An empty block was encountered in an unexpected position.
    UnexpectedEmptyBlock,

    /// Failed to read the doubly-encoded header bytes from the input stream.
    FailedToReadHeaderBytes,

    /// A box key had the wrong number of bytes.
    BadBoxKey,

    /// The message was truncated.
    TruncatedMessage,

    /// The number of receivers exceeds the maximum supported limit.
    TooManyReceivers,

    /// The signer's public key is not in the set of trusted signers.
    UntrustedSigner,

    /// The protocol version in the message is not permitted by the caller's version policy.
    VersionNotAllowed,

    /// A public key failed validation (e.g. all-zero / low-order point).
    BadPublicKey,

    /// A secret key failed validation (e.g. all-zero bytes).
    BadSecretKey,

    /// The message was signed/sent by a different key than expected.
    /// Returned by the `*From` convenience wrappers (`verifyAttachedFrom`,
    /// `verifyDetachedFrom`, `signcryptOpenFrom`) when the actual signer
    /// does not match the caller-supplied expected signer.
    UnexpectedSigner,
};

// ---------------------------------------------------------------------------
// MessageKeyInfo
// ---------------------------------------------------------------------------

/// Information about the keys used for a decrypted/verified message.
/// Returned alongside decrypted content so the caller can inspect
/// which key was used for decryption and who the sender was.
pub const MessageKeyInfo = struct {
    /// The sender's public key bytes, or null if unknown/anonymous.
    sender_key: ?[32]u8 = null,

    /// True if the sender chose to remain anonymous.
    sender_is_anonymous: bool = false,

    /// The index (within the recipient list) of the key that successfully
    /// decrypted the message, or null if not applicable.
    receiver_key_index: ?usize = null,

    /// The total number of recipients in the message header.
    num_recipients: usize = 0,
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "error set members exist" {
    // Verify that each error variant can be created and compared.
    // We use inline assignment to force the compiler to evaluate each member.
    const errors_to_check = [_]Error{
        Error.BadVersion,
        Error.WrongMessageType,
        Error.BadFrame,
        Error.NotASaltpackMessage,
        Error.BadCiphertext,
        Error.NoDecryptionKey,
        Error.BadSenderKeySecretbox,
        Error.DecryptionFailed,
        Error.BadSignature,
        Error.NoSenderKey,
        Error.RepeatedKey,
        Error.BadReceivers,
        Error.BadEphemeralKey,
        Error.TrailingGarbage,
        Error.PacketOverflow,
        Error.UnexpectedEmptyBlock,
        Error.FailedToReadHeaderBytes,
        Error.BadBoxKey,
        Error.TruncatedMessage,
        Error.TooManyReceivers,
        Error.UntrustedSigner,
        Error.VersionNotAllowed,
        Error.BadPublicKey,
        Error.BadSecretKey,
        Error.UnexpectedSigner,
    };

    // Each error should be distinct (not equal to the next one in the list).
    for (errors_to_check[0 .. errors_to_check.len - 1], errors_to_check[1..]) |a, b| {
        try std.testing.expect(a != b);
    }
}

test "error can be used in error union" {
    const MyResult = Error!u32;
    const ok_val: MyResult = 42;
    const err_val: MyResult = Error.BadVersion;

    try std.testing.expectEqual(@as(u32, 42), ok_val catch unreachable);
    try std.testing.expectError(Error.BadVersion, err_val);
}

test "MessageKeyInfo default values" {
    const info = MessageKeyInfo{};
    try std.testing.expect(info.sender_key == null);
    try std.testing.expect(info.sender_is_anonymous == false);
    try std.testing.expect(info.receiver_key_index == null);
    try std.testing.expectEqual(@as(usize, 0), info.num_recipients);
}

test "MessageKeyInfo with values" {
    const sender = [_]u8{0xAB} ** 32;
    const info = MessageKeyInfo{
        .sender_key = sender,
        .sender_is_anonymous = true,
        .receiver_key_index = 3,
        .num_recipients = 5,
    };

    try std.testing.expect(info.sender_key != null);
    try std.testing.expectEqualSlices(u8, &sender, &info.sender_key.?);
    try std.testing.expect(info.sender_is_anonymous == true);
    try std.testing.expectEqual(@as(usize, 3), info.receiver_key_index.?);
    try std.testing.expectEqual(@as(usize, 5), info.num_recipients);
}
