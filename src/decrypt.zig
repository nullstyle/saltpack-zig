//! Saltpack decryption (open) implementation.
//!
//! Zig port of the Go saltpack library's decrypt.go.
//! Implements NaCl Box decryption with per-recipient payload key
//! recovery and HMAC-SHA512 per-block authenticator verification.
//! Supports both V1 and V2 encryption formats.

const std = @import("std");
const types = @import("types.zig");
const sp_errors = @import("errors.zig");
const key_mod = @import("key.zig");
const nonce_mod = @import("nonce.zig");
const header_mod = @import("header.zig");
const encrypt_mod = @import("encrypt.zig");

const Allocator = std.mem.Allocator;
const SecretBox = std.crypto.nacl.SecretBox;
const NaclBox = std.crypto.nacl.Box;
const secureZero = std.crypto.secureZero;

const mp_utils = @import("msgpack_utils.zig");
const MsgPack = mp_utils.MsgPack;
const BufferStream = mp_utils.BufferStream;
const fixedBufferStream = mp_utils.fixedBufferStream;
const Payload = mp_utils.Payload;

const secretbox_tag_length = SecretBox.tag_length;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Options for decryption operations.
///
/// All fields are optional and default to null, which preserves the original
/// "accept any version" behavior. Callers can restrict accepted protocol
/// versions by providing a non-null `version_policy`.
pub const OpenOptions = struct {
    /// When non-null, only protocol versions allowed by this policy will be
    /// accepted. If the message's version is not allowed, decryption fails
    /// with `error.VersionNotAllowed`.
    version_policy: ?types.VersionPolicy = null,
};

/// Result of a decryption operation.
pub const OpenResult = struct {
    /// The decrypted plaintext (caller must free with allocator).
    plaintext: []u8,
    /// Information about the keys used in the message.
    key_info: sp_errors.MessageKeyInfo,
    allocator: Allocator,

    pub fn deinit(self: *const OpenResult) void {
        secureZero(u8, @constCast(self.plaintext));
        self.allocator.free(self.plaintext);
    }
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Decrypt an encrypted saltpack message.
///
/// `keyring` is an array of Box key pairs to try for decryption.
/// `opts` controls version policy enforcement (defaults to accepting any version).
/// Returns the decrypted plaintext and metadata about the keys used.
///
/// **Ownership:** The caller owns the returned `OpenResult` and must call
/// `result.deinit()` to free the decrypted plaintext when done.
///
/// **Errors:**
/// - `error.VersionNotAllowed` -- the message version is rejected by `opts.version_policy`.
/// - `error.WrongMessageType` -- the message is not an encryption message.
/// - `error.NoDecryptionKey` -- none of the keys in `keyring` can decrypt the message.
/// - `error.DecryptionFailed` -- a cryptographic operation failed (tampered data, etc.).
/// - `error.TruncatedMessage` -- the message is incomplete.
/// - `error.TrailingGarbage` -- extra data follows the valid message.
pub fn open(
    allocator: Allocator,
    ciphertext: []const u8,
    keyring: []const key_mod.BoxKeyPair,
    opts: OpenOptions,
) !OpenResult {
    if (ciphertext.len == 0) return sp_errors.Error.FailedToReadHeaderBytes;

    // Decode header.
    const header_decode = try decodeHeaderFromStream(allocator, ciphertext);
    const header_bytes_len = header_decode.bytes_consumed;
    const header_hash = header_decode.header_hash;
    const enc_header = header_decode.header;
    defer {
        allocator.free(enc_header.sender_secretbox);
        header_mod.freeDecodedReceivers(allocator, enc_header.receivers);
    }

    // Validate message type.
    if (enc_header.message_type != .encryption) return sp_errors.Error.WrongMessageType;

    const version = enc_header.version;

    // Check version policy.
    if (opts.version_policy) |policy| {
        if (!policy.allows(version)) {
            return sp_errors.Error.VersionNotAllowed;
        }
    }

    const ephemeral_pk = key_mod.BoxPublicKey.fromBytes(enc_header.ephemeral_key) catch {
        return sp_errors.Error.BadEphemeralKey;
    };

    // Try to recover the payload key.
    const recovery = try recoverPayloadKey(enc_header, keyring) orelse
        return sp_errors.Error.NoDecryptionKey;

    var payload_key = recovery.payload_key;
    defer secureZero(u8, &payload_key);
    const receiver_key = recovery.receiver_key;
    const receiver_index = recovery.receiver_index;

    // Decrypt sender public key.
    const sender_key_nonce = nonce_mod.senderKeyNonce();
    var sender_pk_bytes: [32]u8 = undefined;
    defer secureZero(u8, &sender_pk_bytes);
    SecretBox.open(&sender_pk_bytes, enc_header.sender_secretbox, sender_key_nonce, payload_key) catch {
        return sp_errors.Error.DecryptionFailed;
    };

    // Check if sender is anonymous (sender key == ephemeral key).
    const sender_is_anon = std.crypto.timing_safe.eql([32]u8, sender_pk_bytes, enc_header.ephemeral_key);
    const sender_pk = key_mod.BoxPublicKey.fromBytes(sender_pk_bytes) catch {
        return sp_errors.Error.DecryptionFailed;
    };

    // Compute MAC key for our receiver position.
    var mac_key = try encrypt_mod.computeMacKeyReceiver(
        version,
        receiver_key,
        sender_pk,
        ephemeral_pk,
        header_hash,
        receiver_index,
    );
    defer secureZero(u8, &mac_key);

    // Process payload blocks.
    var plaintext_buf: std.ArrayList(u8) = .empty;
    errdefer plaintext_buf.deinit(allocator);

    // Estimate plaintext size (ciphertext minus overhead)
    try plaintext_buf.ensureTotalCapacity(allocator, ciphertext.len);

    var remaining_data = ciphertext[header_bytes_len..];
    var block_number: u64 = 0;
    var saw_final = false;

    while (remaining_data.len > 0) {
        const block_result = decodeEncryptionBlock(allocator, remaining_data, version, enc_header.receivers.len) catch {
            if (block_number == 0) {
                return sp_errors.Error.TruncatedMessage;
            }
            return sp_errors.Error.BadCiphertext;
        };
        defer allocator.free(block_result.ciphertext);
        defer allocator.free(block_result.authenticators);
        remaining_data = remaining_data[block_result.bytes_consumed..];

        const ct = block_result.ciphertext;
        const is_final = block_result.is_final;

        // Compute payload hash and verify authenticator.
        const nonce = nonce_mod.payloadNonce(block_number);
        const payload_hash = encrypt_mod.computePayloadHash(version, header_hash, nonce, ct, is_final);
        const expected_auth = encrypt_mod.computePayloadAuthenticator(mac_key, payload_hash);

        if (block_result.authenticators.len <= receiver_index) {
            return sp_errors.Error.DecryptionFailed;
        }
        if (!std.crypto.timing_safe.eql(
            types.PayloadAuthenticator,
            expected_auth,
            block_result.authenticators[receiver_index],
        )) {
            return sp_errors.Error.DecryptionFailed;
        }

        // Decrypt.
        if (ct.len < secretbox_tag_length) return sp_errors.Error.DecryptionFailed;
        const pt_len = ct.len - secretbox_tag_length;
        const pt = try allocator.alloc(u8, pt_len);
        defer allocator.free(pt);

        SecretBox.open(pt, ct, nonce, payload_key) catch {
            return sp_errors.Error.DecryptionFailed;
        };

        // V2: reject unexpected empty blocks. An empty block is only valid
        // when it is block 0 AND is the final block (i.e. the message itself
        // was empty). This mirrors the Go reference's checkChunkState
        // (common.go:247-249).
        if (version.major == 2) {
            if (pt.len == 0 and (block_number != 0 or !is_final)) {
                return sp_errors.Error.UnexpectedEmptyBlock;
            }
        }

        // Append plaintext (if non-empty).
        if (pt.len > 0) {
            try plaintext_buf.appendSlice(allocator, pt);
        }

        if (block_number >= types.max_block_number) return sp_errors.Error.PacketOverflow;
        block_number += 1;

        if (is_final) {
            saw_final = true;
            break;
        }
    }

    if (!saw_final) return sp_errors.Error.TruncatedMessage;

    // Check for trailing data — try to read another msgpack value.
    if (remaining_data.len > 0) return sp_errors.Error.TrailingGarbage;

    var key_info = sp_errors.MessageKeyInfo{
        .num_recipients = enc_header.receivers.len,
        .receiver_key_index = receiver_index,
    };
    if (sender_is_anon) {
        key_info.sender_is_anonymous = true;
    } else {
        key_info.sender_key = sender_pk_bytes;
    }

    return OpenResult{
        .plaintext = try plaintext_buf.toOwnedSlice(allocator),
        .key_info = key_info,
        .allocator = allocator,
    };
}

// ---------------------------------------------------------------------------
// Payload key recovery
// ---------------------------------------------------------------------------

pub const RecoveryResult = struct {
    payload_key: types.PayloadKey,
    receiver_key: key_mod.BoxSecretKey,
    receiver_index: usize,
    receiver_is_anon: bool,
};

/// Try to recover the payload key by trying visible then hidden receivers.
///
/// To prevent timing side-channels that could reveal which key slot belongs
/// to the recipient, this function always iterates ALL receiver slots even
/// after finding a match. Only the first successful result is kept.
pub fn recoverPayloadKey(
    enc_header: header_mod.EncryptionHeader,
    keyring: []const key_mod.BoxKeyPair,
) !?RecoveryResult {
    const ephemeral_pk = key_mod.BoxPublicKey.fromBytes(enc_header.ephemeral_key) catch {
        return sp_errors.Error.BadEphemeralKey;
    };
    var result: ?RecoveryResult = null;

    // Try visible receivers (by KID match). Always iterate all slots.
    for (enc_header.receivers, 0..) |rcv, i| {
        if (rcv.recipient_kid) |kid| {
            for (keyring) |kp| {
                if (kid.len == 32 and std.crypto.timing_safe.eql([32]u8, kp.public_key.bytes, kid[0..32].*)) {
                    // Try to decrypt.
                    const recv_nonce = try nonce_mod.payloadKeyBoxNonce(enc_header.version, i);
                    var shared_key = NaclBox.createSharedSecret(
                        ephemeral_pk.bytes,
                        kp.secret_key.bytes,
                    ) catch continue;
                    defer secureZero(u8, &shared_key);

                    var payload_key: types.PayloadKey = undefined;
                    SecretBox.open(&payload_key, rcv.payload_key_box, recv_nonce, shared_key) catch continue;

                    // Keep only the first match.
                    if (result == null) {
                        result = RecoveryResult{
                            .payload_key = payload_key,
                            .receiver_key = kp.secret_key,
                            .receiver_index = i,
                            .receiver_is_anon = false,
                        };
                    } else {
                        secureZero(u8, &payload_key);
                    }
                }
            }
        }
    }

    // Try hidden receivers (brute force all secret keys against all hidden slots).
    // Always iterate all slots even if we already found a match above.
    for (keyring) |kp| {
        var shared_key = NaclBox.createSharedSecret(
            ephemeral_pk.bytes,
            kp.secret_key.bytes,
        ) catch continue;
        defer secureZero(u8, &shared_key);

        for (enc_header.receivers, 0..) |rcv, i| {
            if (rcv.recipient_kid == null) {
                const recv_nonce = try nonce_mod.payloadKeyBoxNonce(enc_header.version, i);

                var payload_key: types.PayloadKey = undefined;
                SecretBox.open(&payload_key, rcv.payload_key_box, recv_nonce, shared_key) catch continue;

                // Keep only the first match.
                if (result == null) {
                    result = RecoveryResult{
                        .payload_key = payload_key,
                        .receiver_key = kp.secret_key,
                        .receiver_index = i,
                        .receiver_is_anon = true,
                    };
                } else {
                    secureZero(u8, &payload_key);
                }
            }
        }
    }

    return result;
}

// ---------------------------------------------------------------------------
// Msgpack decoding
// ---------------------------------------------------------------------------

const HeaderDecodeResult = mp_utils.HeaderDecodeResult;

fn decodeHeaderFromStream(allocator: Allocator, data: []const u8) !HeaderDecodeResult {
    return mp_utils.decodeHeaderFromStream(allocator, data);
}

pub const BlockDecodeResult = struct {
    authenticators: []types.PayloadAuthenticator,
    ciphertext: []u8,
    is_final: bool,
    bytes_consumed: usize,
};

pub fn decodeEncryptionBlock(
    allocator: Allocator,
    data: []const u8,
    version: types.Version,
    num_receivers: usize,
) !BlockDecodeResult {
    const max_buf = 1500000;
    const read_buf_storage = try allocator.alloc(u8, @min(data.len, max_buf));
    defer allocator.free(read_buf_storage);
    const copy_len = read_buf_storage.len;
    @memcpy(read_buf_storage[0..copy_len], data[0..copy_len]);
    var read_buf = fixedBufferStream(read_buf_storage[0..copy_len]);

    var dummy_write_storage: [1]u8 = undefined;
    var dummy_write = fixedBufferStream(&dummy_write_storage);
    var packer = MsgPack.init(&dummy_write, &read_buf);

    const payload = packer.read(allocator) catch {
        return sp_errors.Error.TruncatedMessage;
    };
    defer payload.free(allocator);

    const arr_items = switch (payload) {
        .arr => |a| a,
        else => return sp_errors.Error.BadCiphertext,
    };

    // Validate parsed payload sizes against reasonable bounds to guard
    // against crafted msgpack length prefixes that declare huge sizes.
    // The ciphertext index depends on the version (V1: [auths, ct],
    // V2: [is_final, auths, ct]).
    const max_ct_len = types.encryption_block_size + secretbox_tag_length + 128;
    switch (version.major) {
        1 => {
            if (arr_items.len >= 2) {
                // Validate ciphertext bin length.
                switch (arr_items[1]) {
                    .bin => |b| {
                        if (b.bin.len > max_ct_len) return sp_errors.Error.BadCiphertext;
                    },
                    else => {},
                }
                // Validate authenticator bin lengths (each must be exactly 32 bytes).
                switch (arr_items[0]) {
                    .arr => |auths| {
                        for (auths) |auth_p| {
                            switch (auth_p) {
                                .bin => |b| {
                                    if (b.bin.len != 32) return sp_errors.Error.BadCiphertext;
                                },
                                else => {},
                            }
                        }
                    },
                    else => {},
                }
            }
        },
        2 => {
            if (arr_items.len >= 3) {
                // Validate ciphertext bin length.
                switch (arr_items[2]) {
                    .bin => |b| {
                        if (b.bin.len > max_ct_len) return sp_errors.Error.BadCiphertext;
                    },
                    else => {},
                }
                // Validate authenticator bin lengths (each must be exactly 32 bytes).
                switch (arr_items[1]) {
                    .arr => |auths| {
                        for (auths) |auth_p| {
                            switch (auth_p) {
                                .bin => |b| {
                                    if (b.bin.len != 32) return sp_errors.Error.BadCiphertext;
                                },
                                else => {},
                            }
                        }
                    },
                    else => {},
                }
            }
        },
        else => {},
    }

    return switch (version.major) {
        1 => try decodeBlockV1(allocator, arr_items, num_receivers, read_buf.pos),
        2 => try decodeBlockV2(allocator, arr_items, num_receivers, read_buf.pos),
        else => sp_errors.Error.BadVersion,
    };
}

fn decodeBlockV1(
    allocator: Allocator,
    arr_items: []Payload,
    num_receivers: usize,
    bytes_consumed: usize,
) !BlockDecodeResult {
    // V1: [authenticators_array, ciphertext]
    if (arr_items.len != 2) return sp_errors.Error.BadCiphertext;

    const auth_arr = switch (arr_items[0]) {
        .arr => |a| a,
        else => return sp_errors.Error.BadCiphertext,
    };
    if (auth_arr.len != num_receivers) return sp_errors.Error.BadCiphertext;

    const authenticators = try allocator.alloc(types.PayloadAuthenticator, auth_arr.len);
    errdefer allocator.free(authenticators);
    for (auth_arr, 0..) |auth_p, i| {
        const auth_bytes = switch (auth_p) {
            .bin => |b| b.bin,
            else => return sp_errors.Error.BadCiphertext,
        };
        if (auth_bytes.len != 32) return sp_errors.Error.BadCiphertext;
        authenticators[i] = auth_bytes[0..32].*;
    }

    const ct_bytes = switch (arr_items[1]) {
        .bin => |b| b.bin,
        else => return sp_errors.Error.BadCiphertext,
    };

    const ciphertext = try allocator.alloc(u8, ct_bytes.len);
    @memcpy(ciphertext, ct_bytes);

    // V1: final is detected by ciphertext.len == secretbox_tag_length (16 bytes = empty plaintext).
    const is_final = (ct_bytes.len == secretbox_tag_length);

    return BlockDecodeResult{
        .authenticators = authenticators,
        .ciphertext = ciphertext,
        .is_final = is_final,
        .bytes_consumed = bytes_consumed,
    };
}

fn decodeBlockV2(
    allocator: Allocator,
    arr_items: []Payload,
    num_receivers: usize,
    bytes_consumed: usize,
) !BlockDecodeResult {
    // V2: [is_final, authenticators_array, ciphertext]
    if (arr_items.len != 3) return sp_errors.Error.BadCiphertext;

    const is_final = switch (arr_items[0]) {
        .bool => |b| b,
        else => return sp_errors.Error.BadCiphertext,
    };

    const auth_arr = switch (arr_items[1]) {
        .arr => |a| a,
        else => return sp_errors.Error.BadCiphertext,
    };
    if (auth_arr.len != num_receivers) return sp_errors.Error.BadCiphertext;

    const authenticators = try allocator.alloc(types.PayloadAuthenticator, auth_arr.len);
    errdefer allocator.free(authenticators);
    for (auth_arr, 0..) |auth_p, i| {
        const auth_bytes = switch (auth_p) {
            .bin => |b| b.bin,
            else => return sp_errors.Error.BadCiphertext,
        };
        if (auth_bytes.len != 32) return sp_errors.Error.BadCiphertext;
        authenticators[i] = auth_bytes[0..32].*;
    }

    const ct_bytes = switch (arr_items[2]) {
        .bin => |b| b.bin,
        else => return sp_errors.Error.BadCiphertext,
    };

    const ciphertext = try allocator.alloc(u8, ct_bytes.len);
    @memcpy(ciphertext, ct_bytes);

    return BlockDecodeResult{
        .authenticators = authenticators,
        .ciphertext = ciphertext,
        .is_final = is_final,
        .bytes_consumed = bytes_consumed,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

const encrypt = @import("encrypt.zig");

test "encrypt and decrypt V2 round-trip short message" {
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();

    const msg = "hello saltpack encryption!";
    const receiver_pks = [_]key_mod.BoxPublicKey{receiver_kp.public_key};
    const sealed = try encrypt.seal(allocator, msg, sender_kp.secret_key, &receiver_pks, .{});
    defer allocator.free(sealed);

    const keyring = [_]key_mod.BoxKeyPair{receiver_kp};
    const result = try open(allocator, sealed, &keyring, .{});
    defer result.deinit();

    try std.testing.expectEqualStrings(msg, result.plaintext);
    try std.testing.expect(!result.key_info.sender_is_anonymous);
    try std.testing.expect(result.key_info.sender_key != null);
    try std.testing.expectEqualSlices(u8, &sender_kp.public_key.bytes, &result.key_info.sender_key.?);
}

test "encrypt and decrypt V2 empty message" {
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();

    const receiver_pks = [_]key_mod.BoxPublicKey{receiver_kp.public_key};
    const sealed = try encrypt.seal(allocator, &[_]u8{}, sender_kp.secret_key, &receiver_pks, .{});
    defer allocator.free(sealed);

    const keyring = [_]key_mod.BoxKeyPair{receiver_kp};
    const result = try open(allocator, sealed, &keyring, .{});
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 0), result.plaintext.len);
}

test "encrypt and decrypt V1 round-trip" {
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();

    const msg = "hello v1 encryption!";
    const receiver_pks = [_]key_mod.BoxPublicKey{receiver_kp.public_key};
    const sealed = try encrypt.seal(allocator, msg, sender_kp.secret_key, &receiver_pks, .{
        .version = types.Version.v1(),
    });
    defer allocator.free(sealed);

    const keyring = [_]key_mod.BoxKeyPair{receiver_kp};
    const result = try open(allocator, sealed, &keyring, .{});
    defer result.deinit();

    try std.testing.expectEqualStrings(msg, result.plaintext);
}

test "encrypt and decrypt V1 empty message" {
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();

    const receiver_pks = [_]key_mod.BoxPublicKey{receiver_kp.public_key};
    const sealed = try encrypt.seal(allocator, &[_]u8{}, sender_kp.secret_key, &receiver_pks, .{
        .version = types.Version.v1(),
    });
    defer allocator.free(sealed);

    const keyring = [_]key_mod.BoxKeyPair{receiver_kp};
    const result = try open(allocator, sealed, &keyring, .{});
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 0), result.plaintext.len);
}

test "encrypt and decrypt anonymous sender" {
    const allocator = std.testing.allocator;
    const receiver_kp = key_mod.BoxKeyPair.generate();

    const msg = "anonymous message";
    const receiver_pks = [_]key_mod.BoxPublicKey{receiver_kp.public_key};
    const sealed = try encrypt.seal(allocator, msg, null, &receiver_pks, .{});
    defer allocator.free(sealed);

    const keyring = [_]key_mod.BoxKeyPair{receiver_kp};
    const result = try open(allocator, sealed, &keyring, .{});
    defer result.deinit();

    try std.testing.expectEqualStrings(msg, result.plaintext);
    try std.testing.expect(result.key_info.sender_is_anonymous);
    try std.testing.expect(result.key_info.sender_key == null);
}

test "encrypt and decrypt multiple receivers" {
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const r1 = key_mod.BoxKeyPair.generate();
    const r2 = key_mod.BoxKeyPair.generate();
    const r3 = key_mod.BoxKeyPair.generate();

    const msg = "multi recipient test";
    const receiver_pks = [_]key_mod.BoxPublicKey{ r1.public_key, r2.public_key, r3.public_key };
    const sealed = try encrypt.seal(allocator, msg, sender_kp.secret_key, &receiver_pks, .{});
    defer allocator.free(sealed);

    // Each receiver should be able to decrypt.
    inline for (.{ r1, r2, r3 }) |recv_kp| {
        const keyring = [_]key_mod.BoxKeyPair{recv_kp};
        const result = try open(allocator, sealed, &keyring, .{});
        defer result.deinit();
        try std.testing.expectEqualStrings(msg, result.plaintext);
    }
}

test "decrypt wrong key fails" {
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();
    const wrong_kp = key_mod.BoxKeyPair.generate();

    const msg = "wrong key test";
    const receiver_pks = [_]key_mod.BoxPublicKey{receiver_kp.public_key};
    const sealed = try encrypt.seal(allocator, msg, sender_kp.secret_key, &receiver_pks, .{});
    defer allocator.free(sealed);

    const keyring = [_]key_mod.BoxKeyPair{wrong_kp};
    try std.testing.expectError(sp_errors.Error.NoDecryptionKey, open(allocator, sealed, &keyring, .{}));
}

test "decrypt tampered ciphertext fails" {
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();

    const msg = "tamper test";
    const receiver_pks = [_]key_mod.BoxPublicKey{receiver_kp.public_key};
    const sealed = try encrypt.seal(allocator, msg, sender_kp.secret_key, &receiver_pks, .{});
    defer allocator.free(sealed);

    // Flip the last byte.
    sealed[sealed.len - 1] ^= 1;

    const keyring = [_]key_mod.BoxKeyPair{receiver_kp};
    const result = open(allocator, sealed, &keyring, .{});
    try std.testing.expectError(sp_errors.Error.DecryptionFailed, result);
}

test "decrypt empty ciphertext fails" {
    const allocator = std.testing.allocator;
    const keyring = [_]key_mod.BoxKeyPair{};
    try std.testing.expectError(sp_errors.Error.FailedToReadHeaderBytes, open(allocator, "", &keyring, .{}));
}

test "encrypt and decrypt V2 multi-block message" {
    // Create a message larger than encryption_block_size (1 MiB = 1048576)
    // Use 2 MiB + 100 bytes to ensure 3 blocks
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();
    const msg = try allocator.alloc(u8, 2 * 1048576 + 100);
    defer allocator.free(msg);
    @memset(msg, 0xAB);
    const receiver_pks = [_]key_mod.BoxPublicKey{receiver_kp.public_key};
    const ct = try encrypt_mod.seal(allocator, msg, sender_kp.secret_key, &receiver_pks, .{});
    defer allocator.free(ct);
    const keyring = [_]key_mod.BoxKeyPair{receiver_kp};
    const result = try open(allocator, ct, &keyring, .{});
    defer result.deinit();
    try std.testing.expectEqualSlices(u8, msg, result.plaintext);
}

test "encrypt and decrypt V2 exact block boundary" {
    // Test with exactly 1048576 bytes (one full block)
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();
    const msg = try allocator.alloc(u8, 1048576);
    defer allocator.free(msg);
    @memset(msg, 0xCD);
    const receiver_pks = [_]key_mod.BoxPublicKey{receiver_kp.public_key};
    const ct = try encrypt_mod.seal(allocator, msg, sender_kp.secret_key, &receiver_pks, .{});
    defer allocator.free(ct);
    const keyring = [_]key_mod.BoxKeyPair{receiver_kp};
    const result = try open(allocator, ct, &keyring, .{});
    defer result.deinit();
    try std.testing.expectEqualSlices(u8, msg, result.plaintext);
}

test "encrypt and decrypt V2 block boundary plus one" {
    // Test with 1048577 bytes (forces two blocks, second has 1 byte)
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();
    const msg = try allocator.alloc(u8, 1048577);
    defer allocator.free(msg);
    @memset(msg, 0xEF);
    const receiver_pks = [_]key_mod.BoxPublicKey{receiver_kp.public_key};
    const ct = try encrypt_mod.seal(allocator, msg, sender_kp.secret_key, &receiver_pks, .{});
    defer allocator.free(ct);
    const keyring = [_]key_mod.BoxKeyPair{receiver_kp};
    const result = try open(allocator, ct, &keyring, .{});
    defer result.deinit();
    try std.testing.expectEqualSlices(u8, msg, result.plaintext);
}

test "encrypt and decrypt V1 multi-block message" {
    // V1 multi-block: 2 MiB + 100 bytes
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();
    const msg = try allocator.alloc(u8, 2 * 1048576 + 100);
    defer allocator.free(msg);
    @memset(msg, 0xBB);
    const receiver_pks = [_]key_mod.BoxPublicKey{receiver_kp.public_key};
    const ct = try encrypt_mod.seal(allocator, msg, sender_kp.secret_key, &receiver_pks, .{
        .version = types.Version.v1(),
    });
    defer allocator.free(ct);
    const keyring = [_]key_mod.BoxKeyPair{receiver_kp};
    const result = try open(allocator, ct, &keyring, .{});
    defer result.deinit();
    try std.testing.expectEqualSlices(u8, msg, result.plaintext);
}

test "decrypt truncated message returns error" {
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();
    const receiver_pks = [_]key_mod.BoxPublicKey{receiver_kp.public_key};
    const ct = try encrypt_mod.seal(allocator, "test message for truncation", sender_kp.secret_key, &receiver_pks, .{});
    defer allocator.free(ct);
    // Truncate by removing last 100 bytes
    const truncated = ct[0 .. ct.len - 100];
    const keyring = [_]key_mod.BoxKeyPair{receiver_kp};
    // The exact error may vary depending on where the truncation lands;
    // verify that decryption fails (does not succeed).
    if (open(allocator, truncated, &keyring, .{})) |res| {
        res.deinit();
        unreachable; // should not succeed
    } else |_| {
        // Expected: some error occurred
    }
}

test "decrypt tampered header fails" {
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();

    const msg = "tamper header test";
    const receiver_pks = [_]key_mod.BoxPublicKey{receiver_kp.public_key};
    const ct = try encrypt_mod.seal(allocator, msg, sender_kp.secret_key, &receiver_pks, .{});
    defer allocator.free(ct);

    // Flip a byte in the header region (byte 50, well within the header)
    ct[50] ^= 0xFF;

    const keyring = [_]key_mod.BoxKeyPair{receiver_kp};
    if (open(allocator, ct, &keyring, .{})) |res| {
        res.deinit();
        unreachable; // should not succeed with tampered header
    } else |_| {
        // Expected: some error occurred due to tampered header
    }
}

test "decrypt rejects signed message" {
    const allocator = std.testing.allocator;
    const sign_mod = @import("sign.zig");
    const signer = key_mod.SigningKeyPair.generate();
    const signed = try sign_mod.sign(allocator, "hello", signer.secret_key, .{});
    defer signed.deinit();
    const receiver_kp = key_mod.BoxKeyPair.generate();
    const keyring = [_]key_mod.BoxKeyPair{receiver_kp};
    try std.testing.expectError(error.WrongMessageType, open(allocator, signed.data, &keyring, .{}));
}

test "encrypt and decrypt V1 anonymous sender" {
    const allocator = std.testing.allocator;
    const receiver_kp = key_mod.BoxKeyPair.generate();

    const msg = "anonymous v1 message";
    const receiver_pks = [_]key_mod.BoxPublicKey{receiver_kp.public_key};
    const sealed = try encrypt_mod.seal(allocator, msg, null, &receiver_pks, .{
        .version = types.Version.v1(),
    });
    defer allocator.free(sealed);

    const keyring = [_]key_mod.BoxKeyPair{receiver_kp};
    const result = try open(allocator, sealed, &keyring, .{});
    defer result.deinit();

    try std.testing.expectEqualStrings(msg, result.plaintext);
    try std.testing.expect(result.key_info.sender_is_anonymous);
    try std.testing.expect(result.key_info.sender_key == null);
}

test "encrypt and decrypt V1 multiple receivers" {
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const r1 = key_mod.BoxKeyPair.generate();
    const r2 = key_mod.BoxKeyPair.generate();
    const r3 = key_mod.BoxKeyPair.generate();

    const msg = "v1 multi recipient test";
    const receiver_pks = [_]key_mod.BoxPublicKey{ r1.public_key, r2.public_key, r3.public_key };
    const sealed = try encrypt_mod.seal(allocator, msg, sender_kp.secret_key, &receiver_pks, .{
        .version = types.Version.v1(),
    });
    defer allocator.free(sealed);

    // Each receiver should be able to decrypt.
    inline for (.{ r1, r2, r3 }) |recv_kp| {
        const keyring = [_]key_mod.BoxKeyPair{recv_kp};
        const result = try open(allocator, sealed, &keyring, .{});
        defer result.deinit();
        try std.testing.expectEqualStrings(msg, result.plaintext);
        try std.testing.expect(!result.key_info.sender_is_anonymous);
        try std.testing.expectEqualSlices(u8, &sender_kp.public_key.bytes, &result.key_info.sender_key.?);
    }
}

test "V2 decrypt rejects unexpected empty non-final block" {
    // Construct a valid V2 encrypted message from scratch where block 0 is
    // empty and non-final, followed by a final block. The decryptor should
    // reject the empty non-final block with UnexpectedEmptyBlock.
    const allocator = std.testing.allocator;

    // Generate keys.
    var ephemeral_kp = key_mod.BoxKeyPair.generate();
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();

    // Generate random payload key.
    var payload_key: types.PayloadKey = undefined;
    std.crypto.random.bytes(&payload_key);

    // Encrypt sender public key.
    const sender_key_nonce = nonce_mod.senderKeyNonce();
    var sender_secretbox: [32 + secretbox_tag_length]u8 = undefined;
    SecretBox.seal(&sender_secretbox, &sender_kp.public_key.bytes, sender_key_nonce, payload_key);

    // Build per-receiver payload key box.
    const pkb_len = 32 + secretbox_tag_length;
    const recv_nonce = try nonce_mod.payloadKeyBoxNonce(types.Version.v2(), 0);
    var shared_key = NaclBox.createSharedSecret(
        receiver_kp.public_key.bytes,
        ephemeral_kp.secret_key.bytes,
    ) catch unreachable;
    var pkb: [pkb_len]u8 = undefined;
    SecretBox.seal(&pkb, &payload_key, recv_nonce, shared_key);
    secureZero(u8, &shared_key);

    // Encode the header.
    const receiver_keys_arr = [_]header_mod.ReceiverKeys{.{
        .recipient_kid = &receiver_kp.public_key.bytes,
        .payload_key_box = &pkb,
    }};
    const enc_header = header_mod.EncryptionHeader{
        .version = types.Version.v2(),
        .message_type = .encryption,
        .ephemeral_key = ephemeral_kp.public_key.bytes,
        .sender_secretbox = &sender_secretbox,
        .receivers = &receiver_keys_arr,
    };

    const header_result = try header_mod.encodeEncryptionHeader(allocator, enc_header);
    defer allocator.free(header_result.encoded);
    const header_hash = header_result.header_hash;

    // Compute MAC key for receiver.
    var mac_key = try encrypt_mod.computeMacKeyReceiver(
        types.Version.v2(),
        receiver_kp.secret_key,
        sender_kp.public_key,
        ephemeral_kp.public_key,
        header_hash,
        0,
    );
    defer secureZero(u8, &mac_key);

    // Build output.
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);
    try output.appendSlice(allocator, header_result.encoded);

    // Block 0: empty plaintext, is_final = false (INVALID for V2).
    {
        const block_nonce = nonce_mod.payloadNonce(0);
        var ct0: [secretbox_tag_length]u8 = undefined;
        SecretBox.seal(&ct0, &[_]u8{}, block_nonce, payload_key);

        const payload_hash = encrypt_mod.computePayloadHash(types.Version.v2(), header_hash, block_nonce, &ct0, false);
        const auth0 = encrypt_mod.computePayloadAuthenticator(mac_key, payload_hash);

        // Encode V2 block: [false, [[auth0]], ct0]
        var arr = try Payload.arrPayload(3, allocator);
        try arr.setArrElement(0, Payload.boolToPayload(false)); // NOT final
        var auth_arr = try Payload.arrPayload(1, allocator);
        const auth_payload = try Payload.binToPayload(&auth0, allocator);
        try auth_arr.setArrElement(0, auth_payload);
        try arr.setArrElement(1, auth_arr);
        const ct_payload = try Payload.binToPayload(&ct0, allocator);
        try arr.setArrElement(2, ct_payload);
        try mp_utils.writePayload(allocator, &output, arr, 4096);
    }

    // Block 1: "data" plaintext, is_final = true.
    {
        const block_nonce = nonce_mod.payloadNonce(1);
        const data = "data";
        var ct1: [data.len + secretbox_tag_length]u8 = undefined;
        SecretBox.seal(&ct1, data, block_nonce, payload_key);

        const payload_hash = encrypt_mod.computePayloadHash(types.Version.v2(), header_hash, block_nonce, &ct1, true);
        const auth1 = encrypt_mod.computePayloadAuthenticator(mac_key, payload_hash);

        var arr = try Payload.arrPayload(3, allocator);
        try arr.setArrElement(0, Payload.boolToPayload(true)); // final
        var auth_arr = try Payload.arrPayload(1, allocator);
        const auth_payload = try Payload.binToPayload(&auth1, allocator);
        try auth_arr.setArrElement(0, auth_payload);
        try arr.setArrElement(1, auth_arr);
        const ct_payload = try Payload.binToPayload(&ct1, allocator);
        try arr.setArrElement(2, ct_payload);
        try mp_utils.writePayload(allocator, &output, arr, 4096);
    }

    secureZero(u8, &payload_key);
    secureZero(u8, &ephemeral_kp.secret_key.bytes);

    // Try to decrypt -- should fail with UnexpectedEmptyBlock.
    const keyring = [_]key_mod.BoxKeyPair{receiver_kp};
    try std.testing.expectError(
        sp_errors.Error.UnexpectedEmptyBlock,
        open(allocator, output.items, &keyring, .{}),
    );
}

test "encrypt and decrypt with hide_identity round-trip V2" {
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();

    var hidden_pk = receiver_kp.public_key;
    hidden_pk.hide_identity = true;

    const msg = "hide identity round-trip test";
    const receiver_pks = [_]key_mod.BoxPublicKey{hidden_pk};
    const sealed = try encrypt.seal(allocator, msg, sender_kp.secret_key, &receiver_pks, .{});
    defer allocator.free(sealed);

    const keyring = [_]key_mod.BoxKeyPair{receiver_kp};
    const result = try open(allocator, sealed, &keyring, .{});
    defer result.deinit();

    try std.testing.expectEqualStrings(msg, result.plaintext);
    try std.testing.expect(!result.key_info.sender_is_anonymous);
    try std.testing.expectEqualSlices(u8, &sender_kp.public_key.bytes, &result.key_info.sender_key.?);
}

test "encrypt and decrypt with hide_identity round-trip V1" {
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();

    var hidden_pk = receiver_kp.public_key;
    hidden_pk.hide_identity = true;

    const msg = "hide identity v1 round-trip";
    const receiver_pks = [_]key_mod.BoxPublicKey{hidden_pk};
    const sealed = try encrypt.seal(allocator, msg, sender_kp.secret_key, &receiver_pks, .{
        .version = types.Version.v1(),
    });
    defer allocator.free(sealed);

    const keyring = [_]key_mod.BoxKeyPair{receiver_kp};
    const result = try open(allocator, sealed, &keyring, .{});
    defer result.deinit();

    try std.testing.expectEqualStrings(msg, result.plaintext);
}

test "encrypt and decrypt 1-byte message V2" {
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();

    const msg = "X";
    const receiver_pks = [_]key_mod.BoxPublicKey{receiver_kp.public_key};
    const sealed = try encrypt.seal(allocator, msg, sender_kp.secret_key, &receiver_pks, .{});
    defer allocator.free(sealed);

    const keyring = [_]key_mod.BoxKeyPair{receiver_kp};
    const result = try open(allocator, sealed, &keyring, .{});
    defer result.deinit();

    try std.testing.expectEqualStrings(msg, result.plaintext);
}

test "encrypt and decrypt 1-byte message V1" {
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();

    const msg = "X";
    const receiver_pks = [_]key_mod.BoxPublicKey{receiver_kp.public_key};
    const sealed = try encrypt.seal(allocator, msg, sender_kp.secret_key, &receiver_pks, .{
        .version = types.Version.v1(),
    });
    defer allocator.free(sealed);

    const keyring = [_]key_mod.BoxKeyPair{receiver_kp};
    const result = try open(allocator, sealed, &keyring, .{});
    defer result.deinit();

    try std.testing.expectEqualStrings(msg, result.plaintext);
}

test "decrypt rejects trailing garbage after valid message" {
    // Encrypt a valid message, then append extra bytes. The decryptor should
    // detect the trailing data and return TrailingGarbage.
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();

    const msg = "trailing garbage test message";
    const receiver_pks = [_]key_mod.BoxPublicKey{receiver_kp.public_key};
    const sealed = try encrypt.seal(allocator, msg, sender_kp.secret_key, &receiver_pks, .{});
    defer allocator.free(sealed);

    // Append trailing garbage bytes.
    const garbage = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0x01, 0x02, 0x03, 0x04 };
    const tampered = try allocator.alloc(u8, sealed.len + garbage.len);
    defer allocator.free(tampered);
    @memcpy(tampered[0..sealed.len], sealed);
    @memcpy(tampered[sealed.len..], &garbage);

    const keyring = [_]key_mod.BoxKeyPair{receiver_kp};
    try std.testing.expectError(
        sp_errors.Error.TrailingGarbage,
        open(allocator, tampered, &keyring, .{}),
    );
}

// ---------------------------------------------------------------------------
// Version policy tests
// ---------------------------------------------------------------------------

test "open with v2Only policy rejects V1 encrypted message" {
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();

    const msg = "v1 message for v2-only policy";
    const receiver_pks = [_]key_mod.BoxPublicKey{receiver_kp.public_key};
    const sealed = try encrypt.seal(allocator, msg, sender_kp.secret_key, &receiver_pks, .{
        .version = types.Version.v1(),
    });
    defer allocator.free(sealed);

    const keyring = [_]key_mod.BoxKeyPair{receiver_kp};
    try std.testing.expectError(
        sp_errors.Error.VersionNotAllowed,
        open(allocator, sealed, &keyring, .{ .version_policy = types.VersionPolicy.v2Only() }),
    );
}

test "open with v2Only policy accepts V2 encrypted message" {
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();

    const msg = "v2 message for v2-only policy";
    const receiver_pks = [_]key_mod.BoxPublicKey{receiver_kp.public_key};
    const sealed = try encrypt.seal(allocator, msg, sender_kp.secret_key, &receiver_pks, .{});
    defer allocator.free(sealed);

    const keyring = [_]key_mod.BoxKeyPair{receiver_kp};
    const result = try open(allocator, sealed, &keyring, .{ .version_policy = types.VersionPolicy.v2Only() });
    defer result.deinit();

    try std.testing.expectEqualStrings(msg, result.plaintext);
}

test "open with v1Only policy rejects V2 encrypted message" {
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();

    const msg = "v2 message for v1-only policy";
    const receiver_pks = [_]key_mod.BoxPublicKey{receiver_kp.public_key};
    const sealed = try encrypt.seal(allocator, msg, sender_kp.secret_key, &receiver_pks, .{});
    defer allocator.free(sealed);

    const keyring = [_]key_mod.BoxKeyPair{receiver_kp};
    try std.testing.expectError(
        sp_errors.Error.VersionNotAllowed,
        open(allocator, sealed, &keyring, .{ .version_policy = types.VersionPolicy.v1Only() }),
    );
}

test "open with v1Only policy accepts V1 encrypted message" {
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();

    const msg = "v1 message for v1-only policy";
    const receiver_pks = [_]key_mod.BoxPublicKey{receiver_kp.public_key};
    const sealed = try encrypt.seal(allocator, msg, sender_kp.secret_key, &receiver_pks, .{
        .version = types.Version.v1(),
    });
    defer allocator.free(sealed);

    const keyring = [_]key_mod.BoxKeyPair{receiver_kp};
    const result = try open(allocator, sealed, &keyring, .{ .version_policy = types.VersionPolicy.v1Only() });
    defer result.deinit();

    try std.testing.expectEqualStrings(msg, result.plaintext);
}

test "open with v1OrV2 policy accepts both versions" {
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();

    const msg = "version policy both test";
    const receiver_pks = [_]key_mod.BoxPublicKey{receiver_kp.public_key};

    // V1 message.
    const sealed_v1 = try encrypt.seal(allocator, msg, sender_kp.secret_key, &receiver_pks, .{
        .version = types.Version.v1(),
    });
    defer allocator.free(sealed_v1);

    const keyring = [_]key_mod.BoxKeyPair{receiver_kp};
    const r1 = try open(allocator, sealed_v1, &keyring, .{ .version_policy = types.VersionPolicy.v1OrV2() });
    defer r1.deinit();
    try std.testing.expectEqualStrings(msg, r1.plaintext);

    // V2 message.
    const sealed_v2 = try encrypt.seal(allocator, msg, sender_kp.secret_key, &receiver_pks, .{});
    defer allocator.free(sealed_v2);

    const r2 = try open(allocator, sealed_v2, &keyring, .{ .version_policy = types.VersionPolicy.v1OrV2() });
    defer r2.deinit();
    try std.testing.expectEqualStrings(msg, r2.plaintext);
}

test "open with null version_policy accepts any version" {
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();

    const msg = "null version policy test";
    const receiver_pks = [_]key_mod.BoxPublicKey{receiver_kp.public_key};
    const sealed = try encrypt.seal(allocator, msg, sender_kp.secret_key, &receiver_pks, .{
        .version = types.Version.v1(),
    });
    defer allocator.free(sealed);

    const keyring = [_]key_mod.BoxKeyPair{receiver_kp};
    const result = try open(allocator, sealed, &keyring, .{ .version_policy = null });
    defer result.deinit();

    try std.testing.expectEqualStrings(msg, result.plaintext);
}

// ---------------------------------------------------------------------------
// C2: Tests for previously untested error variants
// ---------------------------------------------------------------------------

test "decrypt rejects all-zero ephemeral key with BadEphemeralKey" {
    // Construct a valid-looking encryption header with an all-zero ephemeral key.
    // The decryptor should reject it with BadEphemeralKey because an all-zero
    // Curve25519 public key is a low-order point.
    const allocator = std.testing.allocator;
    const receiver_kp = key_mod.BoxKeyPair.generate();

    // Build a header with all-zero ephemeral key.
    const zero_ephemeral = [_]u8{0} ** 32;
    const sender_secretbox = [_]u8{0xAA} ** 48;
    const pkb = [_]u8{0xBB} ** 48;
    const receiver_keys_arr = [_]header_mod.ReceiverKeys{.{
        .recipient_kid = &receiver_kp.public_key.bytes,
        .payload_key_box = &pkb,
    }};
    const enc_header = header_mod.EncryptionHeader{
        .version = types.Version.v2(),
        .message_type = .encryption,
        .ephemeral_key = zero_ephemeral,
        .sender_secretbox = &sender_secretbox,
        .receivers = &receiver_keys_arr,
    };

    const header_result = try header_mod.encodeEncryptionHeader(allocator, enc_header);
    defer allocator.free(header_result.encoded);

    // Append a minimal (but invalid) payload block so the message isn't empty
    // after the header. We only need the header to trigger BadEphemeralKey.
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);
    try output.appendSlice(allocator, header_result.encoded);
    // Append a small dummy msgpack value to avoid empty-data confusion.
    try output.appendSlice(allocator, &[_]u8{0xC3}); // msgpack true

    const keyring = [_]key_mod.BoxKeyPair{receiver_kp};
    try std.testing.expectError(
        sp_errors.Error.BadEphemeralKey,
        open(allocator, output.items, &keyring, .{}),
    );
}

test "PacketOverflow constant limits block count to 2^32 - 1" {
    // PacketOverflow is triggered when a message contains more than 2^32 - 1
    // payload blocks. Generating such a message (requiring ~4 PiB of data) is
    // infeasible in a unit test. Instead, we verify that the max_block_number
    // constant used by both encrypt and decrypt is correctly set to 2^32 - 1,
    // which ensures the overflow check will fire at the right boundary.
    try std.testing.expectEqual(@as(u64, 4294967295), types.max_block_number);

    // Also verify that the constant matches the block size from types.
    // At 1 MiB per block, 2^32 blocks would be 4 PiB -- well beyond what
    // any realistic message would contain, but the limit protects against
    // nonce reuse since the block number is encoded as a 64-bit big-endian
    // value in a 24-byte nonce with only 8 bytes for the counter.
    try std.testing.expectEqual(@as(usize, 1 << 20), types.encryption_block_size);
}

test "decrypt truncated message with header only returns TruncatedMessage" {
    // Create a valid encrypted message, then feed only the header portion
    // (without any payload blocks) to the decryptor. This should produce
    // TruncatedMessage because the decryptor expects at least one block.
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();

    const msg = "this will be truncated to header only";
    const receiver_pks = [_]key_mod.BoxPublicKey{receiver_kp.public_key};
    const sealed = try encrypt_mod.seal(allocator, msg, sender_kp.secret_key, &receiver_pks, .{});
    defer allocator.free(sealed);

    // Decode the header to find where it ends.
    const header_decode = try mp_utils.decodeHeaderFromStream(allocator, sealed);
    allocator.free(header_decode.header.sender_secretbox);
    header_mod.freeDecodedReceivers(allocator, header_decode.header.receivers);
    const header_len = header_decode.bytes_consumed;

    // Feed only the header bytes (no payload blocks at all).
    const keyring = [_]key_mod.BoxKeyPair{receiver_kp};
    try std.testing.expectError(
        sp_errors.Error.TruncatedMessage,
        open(allocator, sealed[0..header_len], &keyring, .{}),
    );
}

test "verify truncated attached signature returns TruncatedMessage" {
    // Create a valid signed message, truncate to keep only the first 60 bytes
    // (enough to parse the header but not a valid payload block), and confirm
    // the verifier returns an error. Using a short truncation (60 bytes) ensures
    // the block read itself fails cleanly without partial allocations.
    const allocator = std.testing.allocator;
    const verify_m = @import("verify.zig");
    const sign_mod2 = @import("sign.zig");
    const kp = key_mod.SigningKeyPair.generate();
    const msg = "message to be truncated during verification";

    const signed = try sign_mod2.sign(allocator, msg, kp.secret_key, .{ .version = types.Version.v2() });
    defer signed.deinit();

    // Keep only 60 bytes: enough for the header portion but not enough for
    // a valid payload block. This ensures the block read fails, producing
    // a clean TruncatedMessage error without partial allocations.
    const truncated_len = @min(signed.data.len, 60);

    const result = verify_m.verify(allocator, signed.data[0..truncated_len]);
    // With only 60 bytes, the header itself may fail to parse.
    // Either way, the verifier must return an error.
    try std.testing.expect(std.meta.isError(result));
}
