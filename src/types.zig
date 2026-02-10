//! Common types and constants for the saltpack format.
//!
//! Zig port of the Go saltpack library's const.go and common.go types.

const std = @import("std");

// ---------------------------------------------------------------------------
// Version
// ---------------------------------------------------------------------------

/// Represents a saltpack protocol version (major.minor).
pub const Version = struct {
    major: u32,
    minor: u32,

    /// Returns the Version for Saltpack V1.
    pub fn v1() Version {
        return .{ .major = 1, .minor = 0 };
    }

    /// Returns the Version for Saltpack V2.
    pub fn v2() Version {
        return .{ .major = 2, .minor = 0 };
    }

    /// Returns the current (latest) version.
    pub fn current() Version {
        return v2();
    }

    /// Returns all known saltpack versions.
    pub fn knownVersions() [2]Version {
        return .{ v1(), v2() };
    }

    /// Returns true if two versions are equal.
    pub fn eql(self: Version, other: Version) bool {
        return self.major == other.major and self.minor == other.minor;
    }

    /// Format a Version for display (e.g. "1.0").
    pub fn format(self: Version, writer: anytype) !void {
        try writer.print("{d}.{d}", .{ self.major, self.minor });
    }
};

// ---------------------------------------------------------------------------
// VersionPolicy
// ---------------------------------------------------------------------------

/// Policy for restricting which protocol versions are accepted.
///
/// Use the provided constructors to build a policy:
///   - `VersionPolicy.v1Only()` -- accept only V1 messages
///   - `VersionPolicy.v2Only()` -- accept only V2 messages
///   - `VersionPolicy.v1OrV2()` -- accept both V1 and V2
///
/// Pass `null` where an optional `?VersionPolicy` is expected to accept any
/// known version (the default behavior, equivalent to `v1OrV2()`).
pub const VersionPolicy = struct {
    allow_v1: bool,
    allow_v2: bool,

    /// Accept only V1 messages.
    pub fn v1Only() VersionPolicy {
        return .{ .allow_v1 = true, .allow_v2 = false };
    }

    /// Accept only V2 messages.
    pub fn v2Only() VersionPolicy {
        return .{ .allow_v1 = false, .allow_v2 = true };
    }

    /// Accept both V1 and V2 messages.
    pub fn v1OrV2() VersionPolicy {
        return .{ .allow_v1 = true, .allow_v2 = true };
    }

    /// Returns true if the given version is permitted by this policy.
    pub fn allows(self: VersionPolicy, version: Version) bool {
        if (version.major == 1 and self.allow_v1) return true;
        if (version.major == 2 and self.allow_v2) return true;
        return false;
    }
};

// ---------------------------------------------------------------------------
// MessageType
// ---------------------------------------------------------------------------

/// MessageType describes the type of a saltpack message.
pub const MessageType = enum(u8) {
    encryption = 0,
    attached_signature = 1,
    detached_signature = 2,
    signcryption = 3,

    /// Returns a human-readable description of the message type.
    pub fn toString(self: MessageType) []const u8 {
        return switch (self) {
            .encryption => "an encrypted message",
            .attached_signature => "an attached signature",
            .detached_signature => "a detached signature",
            .signcryption => "a signed and encrypted message",
        };
    }
};

// ---------------------------------------------------------------------------
// Cryptographic type aliases
// ---------------------------------------------------------------------------

/// A symmetric key for NaCl SecretBox (32 bytes).
pub const SymmetricKey = [32]u8;

/// A payload encryption key (32 bytes).
pub const PayloadKey = [32]u8;

/// A NaCl nonce (24 bytes).
pub const Nonce = [24]u8;

/// A SHA-512 header hash (64 bytes).
pub const HeaderHash = [64]u8;

/// An HMAC-SHA512 MAC key, truncated to 32 bytes (crypto_auth_KEYBYTES).
pub const MacKey = [32]u8;

/// A payload authenticator — HMAC-SHA512 truncated to 32 bytes (crypto_auth_BYTES).
pub const PayloadAuthenticator = [32]u8;

/// A 16-byte nonce used in signature operations.
/// Matches the Go reference implementation's `type sigNonce [16]byte`.
pub const SignatureNonce = [16]u8;

// ---------------------------------------------------------------------------
// Constants
// ---------------------------------------------------------------------------

/// The encryption block size (1 MiB). Cannot currently be tweaked.
pub const encryption_block_size: usize = 1 << 20;

/// The signature block size (1 MiB). Cannot currently be tweaked.
pub const signature_block_size: usize = 1 << 20;

/// The publicly advertised name of the format, used in the header and nonce creation.
pub const format_name = "saltpack";

/// Armor header string for encrypted messages.
pub const encryption_armor_string = "ENCRYPTED MESSAGE";

/// Armor header string for signed messages.
pub const signed_armor_string = "SIGNED MESSAGE";

/// Armor header string for detached signatures.
pub const detached_signature_armor_string = "DETACHED SIGNATURE";

/// String mixed into attached signature payloads.
pub const signature_attached_string = "saltpack attached signature\x00";

/// String mixed into detached signature payloads.
pub const signature_detached_string = "saltpack detached signature\x00";

/// String mixed into signcryption signature payloads.
pub const signature_encrypted_string = "saltpack encrypted signature\x00";

/// Context for deriving the signcryption symmetric key.
pub const signcryption_symmetric_key_context = "saltpack signcryption derived symmetric key";

/// Context for deriving the signcryption box key identifier.
pub const signcryption_box_key_identifier_context = "saltpack signcryption box key identifier";

/// The length of HMAC-SHA512 output used for crypto_auth (32 bytes).
const crypto_auth_bytes: usize = 32;

/// The length of the HMAC key for crypto_auth (32 bytes).
const crypto_auth_key_bytes: usize = 32;

/// Maximum block (or sequence) number permitted in a saltpack message.
///
/// Both encryption and signing protocols cap the per-message block counter
/// at 2^32 - 1.  Exceeding this limit produces a `PacketOverflow` error.
pub const max_block_number: u64 = (1 << 32) - 1;

/// Maximum number of receivers supported in a single encrypted message header.
///
/// This limit exists because the header must be fully serialized and parsed
/// as a single msgpack structure. Each receiver entry contributes roughly
/// 120 bytes to the serialized header (32-byte KID + ~80-byte payload_key_box
/// + msgpack framing overhead). A limit of 2048 receivers keeps the header
/// at a manageable size (~250 KB) while supporting large recipient lists.
///
/// Exceeding this limit will produce a `TooManyReceivers` error during
/// both encoding and decoding.
pub const max_receiver_count: usize = 2048;

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "Version v1 and v2 constructors" {
    const v1 = Version.v1();
    try std.testing.expectEqual(@as(u32, 1), v1.major);
    try std.testing.expectEqual(@as(u32, 0), v1.minor);

    const v2 = Version.v2();
    try std.testing.expectEqual(@as(u32, 2), v2.major);
    try std.testing.expectEqual(@as(u32, 0), v2.minor);
}

test "Version equality" {
    const v1a = Version.v1();
    const v1b = Version.v1();
    const v2 = Version.v2();

    try std.testing.expect(v1a.eql(v1b));
    try std.testing.expect(!v1a.eql(v2));
    try std.testing.expect(v2.eql(v2));
}

test "Version current is v2" {
    const cur = Version.current();
    try std.testing.expect(cur.eql(Version.v2()));
}

test "Version knownVersions" {
    const known = Version.knownVersions();
    try std.testing.expectEqual(@as(usize, 2), known.len);
    try std.testing.expect(known[0].eql(Version.v1()));
    try std.testing.expect(known[1].eql(Version.v2()));
}

test "Version format" {
    const v1 = Version.v1();
    var buf: [32]u8 = undefined;
    const result = std.fmt.bufPrint(&buf, "{f}", .{v1}) catch unreachable;
    try std.testing.expectEqualStrings("1.0", result);
}

test "MessageType integer values" {
    try std.testing.expectEqual(@as(u8, 0), @intFromEnum(MessageType.encryption));
    try std.testing.expectEqual(@as(u8, 1), @intFromEnum(MessageType.attached_signature));
    try std.testing.expectEqual(@as(u8, 2), @intFromEnum(MessageType.detached_signature));
    try std.testing.expectEqual(@as(u8, 3), @intFromEnum(MessageType.signcryption));
}

test "MessageType toString" {
    try std.testing.expectEqualStrings("an encrypted message", MessageType.encryption.toString());
    try std.testing.expectEqualStrings("an attached signature", MessageType.attached_signature.toString());
    try std.testing.expectEqualStrings("a detached signature", MessageType.detached_signature.toString());
    try std.testing.expectEqualStrings("a signed and encrypted message", MessageType.signcryption.toString());
}

test "constants" {
    try std.testing.expectEqual(@as(usize, 1048576), encryption_block_size);
    try std.testing.expectEqual(@as(usize, 1048576), signature_block_size);
    try std.testing.expectEqualStrings("saltpack", format_name);
    try std.testing.expectEqual(@as(usize, 32), crypto_auth_bytes);
    try std.testing.expectEqual(@as(usize, 32), crypto_auth_key_bytes);
    try std.testing.expectEqual(@as(usize, 2048), max_receiver_count);
}

test "type alias sizes" {
    try std.testing.expectEqual(@as(usize, 32), @sizeOf(SymmetricKey));
    try std.testing.expectEqual(@as(usize, 32), @sizeOf(PayloadKey));
    try std.testing.expectEqual(@as(usize, 24), @sizeOf(Nonce));
    try std.testing.expectEqual(@as(usize, 64), @sizeOf(HeaderHash));
    try std.testing.expectEqual(@as(usize, 32), @sizeOf(MacKey));
    try std.testing.expectEqual(@as(usize, 32), @sizeOf(PayloadAuthenticator));
    try std.testing.expectEqual(@as(usize, 16), @sizeOf(SignatureNonce));
}

test "VersionPolicy v1Only allows V1 rejects V2" {
    const policy = VersionPolicy.v1Only();
    try std.testing.expect(policy.allows(Version.v1()));
    try std.testing.expect(!policy.allows(Version.v2()));
}

test "VersionPolicy v2Only allows V2 rejects V1" {
    const policy = VersionPolicy.v2Only();
    try std.testing.expect(!policy.allows(Version.v1()));
    try std.testing.expect(policy.allows(Version.v2()));
}

test "VersionPolicy v1OrV2 allows both" {
    const policy = VersionPolicy.v1OrV2();
    try std.testing.expect(policy.allows(Version.v1()));
    try std.testing.expect(policy.allows(Version.v2()));
}

test "VersionPolicy rejects unknown versions" {
    const policy = VersionPolicy.v1OrV2();
    const v99 = Version{ .major = 99, .minor = 0 };
    try std.testing.expect(!policy.allows(v99));
}
