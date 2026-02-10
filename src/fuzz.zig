//! Fuzz testing for adversarial input resilience.
//!
//! Exercises the saltpack parsing and decryption surfaces with random bytes
//! to verify that:
//!   - No code path panics or crashes on malformed input.
//!   - All errors are caught and returned gracefully.
//!   - The testing allocator detects no memory leaks.
//!
//! Run in normal (non-fuzz) mode:
//!   zig build test --summary all
//!
//! Run in continuous fuzz mode:
//!   zig build test --fuzz
//!
//! Each fuzz target follows the same pattern:
//!   1. Obtain adversarial bytes via `std.testing.fuzz`.
//!   2. Call the target function with `std.testing.allocator`.
//!   3. On success, properly free the result.
//!   4. On error, do nothing (all errors are acceptable).

const std = @import("std");
const header = @import("header.zig");
const armor = @import("armor.zig");
const decrypt = @import("decrypt.zig");
const verify = @import("verify.zig");
const signcrypt = @import("signcrypt.zig");
const key = @import("key.zig");
const mp_utils = @import("msgpack_utils.zig");

// ---------------------------------------------------------------------------
// 1. Header parsing fuzz
// ---------------------------------------------------------------------------

test "fuzz: header decoding handles arbitrary bytes" {
    try std.testing.fuzz({}, fuzzHeaderDecode, .{});
}

fn fuzzHeaderDecode(_: void, input: []const u8) anyerror!void {
    const allocator = std.testing.allocator;

    const decoded = header.decodeHeader(allocator, input) catch return;

    // Successfully decoded -- free all allocations.
    switch (decoded) {
        .encryption => |enc| {
            allocator.free(enc.header.sender_secretbox);
            header.freeDecodedReceivers(allocator, enc.header.receivers);
        },
        .signature => {
            // SignatureHeader has no heap allocations to free.
        },
    }
}

// ---------------------------------------------------------------------------
// 2. Msgpack decoding fuzz
// ---------------------------------------------------------------------------

test "fuzz: msgpack decoding handles arbitrary bytes" {
    try std.testing.fuzz({}, fuzzMsgpackDecode, .{});
}

fn fuzzMsgpackDecode(_: void, input: []const u8) anyerror!void {
    const allocator = std.testing.allocator;

    if (input.len == 0) return;

    // Copy input into a mutable buffer since the msgpack reader requires it.
    const buf = try allocator.alloc(u8, input.len);
    defer allocator.free(buf);
    @memcpy(buf, input);

    var read_buf = mp_utils.fixedBufferStream(buf);
    var dummy_write_storage: [1]u8 = undefined;
    var dummy_write = mp_utils.fixedBufferStream(&dummy_write_storage);

    var packer = mp_utils.MsgPack.init(&dummy_write, &read_buf);

    const payload = packer.read(allocator) catch return;
    payload.free(allocator);
}

// ---------------------------------------------------------------------------
// 3. Decrypt with garbage fuzz
// ---------------------------------------------------------------------------

test "fuzz: decrypt.open handles arbitrary bytes" {
    try std.testing.fuzz({}, fuzzDecryptOpen, .{});
}

fn fuzzDecryptOpen(_: void, input: []const u8) anyerror!void {
    const allocator = std.testing.allocator;

    // Use a dummy keyring -- we don't expect decryption to succeed,
    // but the code path should handle the garbage gracefully.
    const dummy_kp = key.BoxKeyPair.generate();
    const keyring = [_]key.BoxKeyPair{dummy_kp};

    const result = decrypt.open(allocator, input, &keyring, .{}) catch return;
    result.deinit();
}

// ---------------------------------------------------------------------------
// 4. Verify with garbage fuzz
// ---------------------------------------------------------------------------

test "fuzz: verify.verify handles arbitrary bytes" {
    try std.testing.fuzz({}, fuzzVerify, .{});
}

fn fuzzVerify(_: void, input: []const u8) anyerror!void {
    const allocator = std.testing.allocator;

    const result = verify.verify(allocator, input) catch return;
    result.deinit();
}

test "fuzz: verify.verifyDetached handles arbitrary bytes" {
    try std.testing.fuzz({}, fuzzVerifyDetached, .{});
}

fn fuzzVerifyDetached(_: void, input: []const u8) anyerror!void {
    const allocator = std.testing.allocator;

    // Split input in half: first half is "message", second half is "signature".
    const mid = input.len / 2;
    const message = input[0..mid];
    const signature_msg = input[mid..];

    const result = verify.verifyDetached(allocator, message, signature_msg) catch return;
    result.deinit();
}

// ---------------------------------------------------------------------------
// 5. Armor decoding fuzz
// ---------------------------------------------------------------------------

test "fuzz: armor.decode handles arbitrary bytes" {
    try std.testing.fuzz({}, fuzzArmorDecode, .{});
}

fn fuzzArmorDecode(_: void, input: []const u8) anyerror!void {
    const allocator = std.testing.allocator;

    const result = armor.decode(allocator, input) catch return;
    allocator.free(result.data);
}

// ---------------------------------------------------------------------------
// 6. Signcrypt open with garbage fuzz
// ---------------------------------------------------------------------------

test "fuzz: signcrypt.open handles arbitrary bytes" {
    try std.testing.fuzz({}, fuzzSigncryptOpen, .{});
}

fn fuzzSigncryptOpen(_: void, input: []const u8) anyerror!void {
    const allocator = std.testing.allocator;

    // Use a dummy keyring and no signing key lookup.
    const dummy_kp = key.BoxKeyPair.generate();
    const keyring = [_]key.BoxKeyPair{dummy_kp};

    const lookup = struct {
        fn lookupFn(pk_bytes: [32]u8) ?key.SigningPublicKey {
            return key.SigningPublicKey.fromBytes(pk_bytes) catch return null;
        }
    };

    const result = signcrypt.open(allocator, input, &keyring, &lookup.lookupFn, .{}) catch return;
    result.deinit();
}
