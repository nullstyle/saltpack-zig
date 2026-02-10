//! Nonce construction for all saltpack cryptographic contexts.
//!
//! Each saltpack operation uses a distinct nonce pattern to ensure domain
//! separation. This module implements every nonce pattern described in the
//! saltpack specification.

const std = @import("std");
const types = @import("types.zig");
const sp_errors = @import("errors.zig");

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Returns the fixed nonce for encrypting the sender key secretbox.
/// Literal string: "saltpack_sender_key_sbox" (exactly 24 bytes).
pub fn senderKeyNonce() types.Nonce {
    return "saltpack_sender_key_sbox".*;
}

/// Returns the nonce for encrypting the payload key box to a recipient.
///
/// - **v1**: literal string `"saltpack_payload_key_box"` (24 bytes).
/// - **v2**: `"saltpack_recipsb"` (16 bytes) || big-endian uint64(recipient_index).
pub fn payloadKeyBoxNonce(version: types.Version, recipient_index: u64) sp_errors.Error!types.Nonce {
    return switch (version.major) {
        1 => "saltpack_payload_key_box".*,
        2 => payloadKeyBoxNonceV2(recipient_index),
        else => sp_errors.Error.BadVersion,
    };
}

/// Returns the nonce for encrypting a payload block.
/// `"saltpack_ploadsb"` (16 bytes) || big-endian uint64(block_number).
pub fn payloadNonce(block_number: u64) types.Nonce {
    var n: types.Nonce = undefined;
    const prefix = "saltpack_ploadsb";
    @memcpy(n[0..16], prefix);
    std.mem.writeInt(u64, n[16..24], block_number, .big);
    return n;
}

/// Returns the nonce for MAC key derivation.
///
/// - **v1**: first 24 bytes of header_hash.
/// - **v2**: first 16 bytes of header_hash (with LSB of byte 15 encoding
///   sender vs ephemeral: 0 for sender, 1 for ephemeral) || big-endian
///   uint64(recipient_index).
pub fn macKeyNonce(version: types.Version, header_hash: types.HeaderHash, recipient_index: u64, is_ephemeral: bool) sp_errors.Error!types.Nonce {
    return switch (version.major) {
        1 => macKeyNonceV1(header_hash),
        2 => macKeyNonceV2(header_hash, recipient_index, is_ephemeral),
        else => sp_errors.Error.BadVersion,
    };
}

/// Returns the fixed nonce for signcryption derived key computation.
/// Literal string: "saltpack_derived_sboxkey" (exactly 24 bytes).
pub fn signcryptDerivedKeyNonce() types.Nonce {
    return "saltpack_derived_sboxkey".*;
}

/// Returns the nonce for a signcryption payload block.
/// First 16 bytes of header_hash (with LSB of byte 15 encoding finality:
/// 0 for not final, 1 for final) || big-endian uint64(block_number).
pub fn signcryptPayloadNonce(header_hash: types.HeaderHash, block_number: u64, is_final: bool) types.Nonce {
    var n: types.Nonce = undefined;
    @memcpy(n[0..16], header_hash[0..16]);
    // Clear LSB of byte 15, then set it if is_final.
    n[15] &= 0xFE;
    if (is_final) {
        n[15] |= 1;
    }
    std.mem.writeInt(u64, n[16..24], block_number, .big);
    return n;
}

/// Generates a random 16-byte signature nonce using the system CSPRNG.
/// Matches the Go reference implementation's `sigNonce` (16 bytes).
pub fn generateSignatureNonce() types.SignatureNonce {
    var n: types.SignatureNonce = undefined;
    std.crypto.random.bytes(&n);
    return n;
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

fn payloadKeyBoxNonceV2(recipient_index: u64) types.Nonce {
    var n: types.Nonce = undefined;
    const prefix = "saltpack_recipsb";
    @memcpy(n[0..16], prefix);
    std.mem.writeInt(u64, n[16..24], recipient_index, .big);
    return n;
}

fn macKeyNonceV1(header_hash: types.HeaderHash) types.Nonce {
    return header_hash[0..24].*;
}

fn macKeyNonceV2(header_hash: types.HeaderHash, recipient_index: u64, is_ephemeral: bool) types.Nonce {
    var n: types.Nonce = undefined;
    @memcpy(n[0..16], header_hash[0..16]);
    // Clear LSB of byte 15, then set it if is_ephemeral.
    n[15] &= 0xFE;
    if (is_ephemeral) {
        n[15] |= 1;
    }
    std.mem.writeInt(u64, n[16..24], recipient_index, .big);
    return n;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "sender key nonce is correct string" {
    const n = senderKeyNonce();
    try std.testing.expectEqualSlices(u8, "saltpack_sender_key_sbox", &n);
    try std.testing.expectEqual(@as(usize, 24), n.len);
}

test "payload key box nonce v1" {
    const n = try payloadKeyBoxNonce(types.Version.v1(), 0);
    try std.testing.expectEqualSlices(u8, "saltpack_payload_key_box", &n);

    // For v1, the recipient index is ignored — all indices yield the same nonce.
    const n2 = try payloadKeyBoxNonce(types.Version.v1(), 42);
    try std.testing.expectEqualSlices(u8, &n, &n2);
}

test "payload key box nonce v2 index 0" {
    const n = try payloadKeyBoxNonce(types.Version.v2(), 0);
    // First 16 bytes are the prefix.
    try std.testing.expectEqualSlices(u8, "saltpack_recipsb", n[0..16]);
    // Last 8 bytes are big-endian 0.
    const expected_tail = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0 };
    try std.testing.expectEqualSlices(u8, &expected_tail, n[16..24]);
}

test "payload key box nonce v2 index 5" {
    const n = try payloadKeyBoxNonce(types.Version.v2(), 5);
    try std.testing.expectEqualSlices(u8, "saltpack_recipsb", n[0..16]);
    // 5 in big-endian u64: 0x0000000000000005
    const expected_tail = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 5 };
    try std.testing.expectEqualSlices(u8, &expected_tail, n[16..24]);
}

test "payload nonce block 0" {
    const n = payloadNonce(0);
    try std.testing.expectEqualSlices(u8, "saltpack_ploadsb", n[0..16]);
    const expected_tail = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 0 };
    try std.testing.expectEqualSlices(u8, &expected_tail, n[16..24]);
}

test "payload nonce block 1" {
    const n = payloadNonce(1);
    try std.testing.expectEqualSlices(u8, "saltpack_ploadsb", n[0..16]);
    const expected_tail = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 1 };
    try std.testing.expectEqualSlices(u8, &expected_tail, n[16..24]);
}

test "mac key nonce v1" {
    // Use a known header hash.
    var hh: types.HeaderHash = undefined;
    for (&hh, 0..) |*b, i| {
        b.* = @truncate(i);
    }
    const n = try macKeyNonce(types.Version.v1(), hh, 0, false);
    // Should be exactly the first 24 bytes of the header hash.
    try std.testing.expectEqualSlices(u8, hh[0..24], &n);
}

test "mac key nonce v2 sender" {
    // Create a header hash with a known pattern; set byte 15 to 0xFF to
    // test that the LSB is cleared (sender = 0).
    var hh: types.HeaderHash = [_]u8{0} ** 64;
    hh[15] = 0xFF; // all bits set
    const n = try macKeyNonce(types.Version.v2(), hh, 7, false);

    // Byte 15 should have its LSB cleared: 0xFF & 0xFE = 0xFE.
    try std.testing.expectEqual(@as(u8, 0xFE), n[15]);

    // First 15 bytes match header hash.
    try std.testing.expectEqualSlices(u8, hh[0..15], n[0..15]);

    // Last 8 bytes are big-endian 7.
    const expected_tail = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 7 };
    try std.testing.expectEqualSlices(u8, &expected_tail, n[16..24]);
}

test "mac key nonce v2 ephemeral" {
    // Create a header hash with byte 15 = 0x00 to test that LSB is set.
    var hh: types.HeaderHash = [_]u8{0} ** 64;
    hh[15] = 0x00;
    const n = try macKeyNonce(types.Version.v2(), hh, 3, true);

    // Byte 15 should have its LSB set: 0x00 | 0x01 = 0x01.
    try std.testing.expectEqual(@as(u8, 0x01), n[15]);

    // Last 8 bytes are big-endian 3.
    const expected_tail = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 3 };
    try std.testing.expectEqualSlices(u8, &expected_tail, n[16..24]);
}

test "signcrypt derived key nonce" {
    const n = signcryptDerivedKeyNonce();
    try std.testing.expectEqualSlices(u8, "saltpack_derived_sboxkey", &n);
    try std.testing.expectEqual(@as(usize, 24), n.len);
}

test "signcrypt payload nonce not final" {
    var hh: types.HeaderHash = [_]u8{0xAB} ** 64;
    hh[15] = 0xFF; // all bits set — LSB should be cleared
    const n = signcryptPayloadNonce(hh, 42, false);

    // Byte 15: 0xFF & 0xFE = 0xFE (not final, LSB = 0).
    try std.testing.expectEqual(@as(u8, 0xFE), n[15]);

    // First 15 bytes match header hash.
    try std.testing.expectEqualSlices(u8, &([_]u8{0xAB} ** 15), n[0..15]);

    // Last 8 bytes are big-endian 42.
    const expected_tail = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 42 };
    try std.testing.expectEqualSlices(u8, &expected_tail, n[16..24]);
}

test "signcrypt payload nonce is final" {
    const hh: types.HeaderHash = [_]u8{0x00} ** 64;
    const n = signcryptPayloadNonce(hh, 10, true);

    // Byte 15: 0x00 | 0x01 = 0x01 (final, LSB = 1).
    try std.testing.expectEqual(@as(u8, 0x01), n[15]);

    // Last 8 bytes are big-endian 10.
    const expected_tail = [_]u8{ 0, 0, 0, 0, 0, 0, 0, 10 };
    try std.testing.expectEqualSlices(u8, &expected_tail, n[16..24]);
}

test "signature nonce is random" {
    const n1 = generateSignatureNonce();
    const n2 = generateSignatureNonce();

    // Two successive calls should produce different values
    // (probability of collision with 128 bits of randomness is negligible).
    try std.testing.expect(!std.mem.eql(u8, &n1, &n2));

    // Each nonce is 16 bytes (matching Go's sigNonce).
    try std.testing.expectEqual(@as(usize, 16), n1.len);
    try std.testing.expectEqual(@as(usize, 16), n2.len);
}
