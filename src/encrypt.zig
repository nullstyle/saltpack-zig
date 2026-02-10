//! Saltpack encryption (seal) implementation.
//!
//! Zig port of the Go saltpack library's encrypt.go.
//! Implements NaCl Box encryption with per-recipient payload key
//! distribution and HMAC-SHA512 per-block authenticators.
//! Supports both V1 and V2 encryption formats.

const std = @import("std");
const types = @import("types.zig");
const sp_errors = @import("errors.zig");
const key_mod = @import("key.zig");
const nonce_mod = @import("nonce.zig");
const header_mod = @import("header.zig");

const Allocator = std.mem.Allocator;
const Sha512 = std.crypto.hash.sha2.Sha512;
const HmacSha512 = std.crypto.auth.hmac.sha2.HmacSha512;
const SecretBox = std.crypto.nacl.SecretBox;
const NaclBox = std.crypto.nacl.Box;

const mp_utils = @import("msgpack_utils.zig");
const Payload = mp_utils.Payload;

const secretbox_tag_length = SecretBox.tag_length;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Options for encryption operations.
pub const SealOptions = struct {
    version: types.Version = types.Version.v2(),
};

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Encrypt a plaintext message for the given receivers.
///
/// `sender` is the sender's Box secret key. If null, the ephemeral key
/// is used as the sender (anonymous mode).
/// Returns the encrypted message bytes (caller owns the returned memory).
pub fn seal(
    allocator: Allocator,
    plaintext: []const u8,
    sender: ?key_mod.BoxSecretKey,
    receivers: []const key_mod.BoxPublicKey,
    opts: SealOptions,
) ![]u8 {
    if (receivers.len == 0) return sp_errors.Error.BadReceivers;
    if (receivers.len > types.max_receiver_count) return sp_errors.Error.BadReceivers;

    // Fix 5 (M11): Check for duplicate receiver keys.
    for (receivers, 0..) |r1, i| {
        for (receivers[i + 1 ..]) |r2| {
            if (std.crypto.timing_safe.eql([32]u8, r1.bytes, r2.bytes)) {
                return sp_errors.Error.RepeatedKey;
            }
        }
    }

    // Generate ephemeral key pair.
    var ephemeral_kp = key_mod.BoxKeyPair.generate();
    // Fix 1 (C1): Zero ephemeral secret key after use.
    defer std.crypto.secureZero(u8, &ephemeral_kp.secret_key.bytes);

    // Determine the effective sender key (use ephemeral if anonymous).
    var effective_sender: key_mod.BoxSecretKey = sender orelse ephemeral_kp.secret_key;
    defer std.crypto.secureZero(u8, &effective_sender.bytes);

    // Generate random payload key.
    var payload_key: types.PayloadKey = undefined;
    std.crypto.random.bytes(&payload_key);
    // Fix 1 (C1): Zero payload key after use.
    defer std.crypto.secureZero(u8, &payload_key);

    // Encrypt sender public key with payload key.
    const sender_key_nonce = nonce_mod.senderKeyNonce();
    var sender_secretbox: [32 + secretbox_tag_length]u8 = undefined;
    SecretBox.seal(&sender_secretbox, &effective_sender.getPublicKey().bytes, sender_key_nonce, payload_key);

    // Fix 2 (C2): Create shuffled index mapping for receiver privacy.
    const indices = try allocator.alloc(usize, receivers.len);
    defer allocator.free(indices);
    for (indices, 0..) |*idx, i| idx.* = i;
    if (indices.len > 1) {
        var si: usize = indices.len - 1;
        while (si > 0) : (si -= 1) {
            const j = std.crypto.random.intRangeLessThan(usize, 0, si + 1);
            std.mem.swap(usize, &indices[si], &indices[j]);
        }
    }

    // Build per-receiver payload key boxes (in shuffled order).
    const pkb_len = 32 + secretbox_tag_length;
    const receiver_keys = try allocator.alloc(header_mod.ReceiverKeys, receivers.len);
    defer allocator.free(receiver_keys);

    const pkb_storage = try allocator.alloc(u8, receivers.len * pkb_len);
    defer allocator.free(pkb_storage);

    for (indices, 0..) |orig_idx, i| {
        const recv_pk = receivers[orig_idx];
        const recv_nonce = try nonce_mod.payloadKeyBoxNonce(opts.version, i);

        // DH(ephemeral_private, receiver_public) then SecretBox encrypt payload key.
        var shared_key = NaclBox.createSharedSecret(recv_pk.bytes, ephemeral_kp.secret_key.bytes) catch {
            return sp_errors.Error.BadEphemeralKey;
        };
        // Fix 1 (C1): Zero shared key after use.
        defer std.crypto.secureZero(u8, &shared_key);

        const pkb_slice = pkb_storage[i * pkb_len .. (i + 1) * pkb_len];
        SecretBox.seal(pkb_slice, &payload_key, recv_nonce, shared_key);

        // Fix 6 (M12): Support hide_identity flag.
        // Use a pointer into the caller's receivers slice (stable lifetime).
        receiver_keys[i] = .{
            .recipient_kid = if (recv_pk.hide_identity) null else &receivers[orig_idx].bytes,
            .payload_key_box = pkb_slice,
        };
    }

    // Encode header.
    const enc_header = header_mod.EncryptionHeader{
        .version = opts.version,
        .message_type = .encryption,
        .ephemeral_key = ephemeral_kp.public_key.bytes,
        .sender_secretbox = &sender_secretbox,
        .receivers = receiver_keys,
    };

    const header_result = try header_mod.encodeEncryptionHeader(allocator, enc_header);
    defer allocator.free(header_result.encoded);
    const header_hash = header_result.header_hash;

    // Build shuffled receivers array for MAC key computation.
    const shuffled_receivers = try allocator.alloc(key_mod.BoxPublicKey, receivers.len);
    defer allocator.free(shuffled_receivers);
    for (indices, 0..) |orig_idx, i| shuffled_receivers[i] = receivers[orig_idx];

    // Compute MAC keys for each receiver (in shuffled order).
    const mac_keys = try computeMacKeysSender(
        allocator,
        opts.version,
        effective_sender,
        ephemeral_kp.secret_key,
        shuffled_receivers,
        header_hash,
    );
    // Fix 1 (C1): Zero mac keys before freeing.
    defer {
        for (mac_keys) |*k| std.crypto.secureZero(u8, k);
        allocator.free(mac_keys);
    }

    // Fix 7 (H8): Pre-size output ArrayList.
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);
    const block_size = types.encryption_block_size;
    const num_blocks = if (plaintext.len == 0) 1 else (plaintext.len + block_size - 1) / block_size;
    const estimated_size = @min(
        std.math.maxInt(usize) / 2,
        header_result.encoded.len +| (num_blocks *| (block_size +| (256 *| receivers.len) +| 128)),
    );
    try output.ensureTotalCapacity(allocator, estimated_size);
    try output.appendSlice(allocator, header_result.encoded);

    // Encrypt payload blocks.
    var block_number: u64 = 0;
    var offset: usize = 0;

    switch (opts.version.major) {
        1 => {
            // V1: data blocks + always an empty final block.
            while (offset < plaintext.len) {
                const end = @min(offset + block_size, plaintext.len);
                const chunk = plaintext[offset..end];

                try encryptAndAppendBlock(
                    allocator,
                    &output,
                    opts.version,
                    header_hash,
                    payload_key,
                    mac_keys,
                    chunk,
                    block_number,
                    false,
                );

                if (block_number >= types.max_block_number) return sp_errors.Error.PacketOverflow;
                block_number += 1;
                offset = end;
            }
            // Final empty block.
            try encryptAndAppendBlock(
                allocator,
                &output,
                opts.version,
                header_hash,
                payload_key,
                mac_keys,
                &[_]u8{},
                block_number,
                true,
            );
        },
        2 => {
            // V2: last data block has is_final=true.
            if (plaintext.len == 0) {
                try encryptAndAppendBlock(
                    allocator,
                    &output,
                    opts.version,
                    header_hash,
                    payload_key,
                    mac_keys,
                    &[_]u8{},
                    block_number,
                    true,
                );
            } else {
                while (offset < plaintext.len) {
                    const end = @min(offset + block_size, plaintext.len);
                    const chunk = plaintext[offset..end];
                    const is_final = (end == plaintext.len);

                    try encryptAndAppendBlock(
                        allocator,
                        &output,
                        opts.version,
                        header_hash,
                        payload_key,
                        mac_keys,
                        chunk,
                        block_number,
                        is_final,
                    );

                    if (block_number >= types.max_block_number) return sp_errors.Error.PacketOverflow;
                    block_number += 1;
                    offset = end;
                }
            }
        },
        else => return sp_errors.Error.BadVersion,
    }

    return try output.toOwnedSlice(allocator);
}

// ---------------------------------------------------------------------------
// Per-block encryption
// ---------------------------------------------------------------------------

fn encryptAndAppendBlock(
    allocator: Allocator,
    output: *std.ArrayList(u8),
    version: types.Version,
    header_hash: types.HeaderHash,
    payload_key: types.PayloadKey,
    mac_keys: []const types.MacKey,
    chunk: []const u8,
    block_number: u64,
    is_final: bool,
) !void {
    // Encrypt the chunk with SecretBox.
    const nonce = nonce_mod.payloadNonce(block_number);
    const ct_len = chunk.len + secretbox_tag_length;
    const ciphertext = try allocator.alloc(u8, ct_len);
    defer allocator.free(ciphertext);
    SecretBox.seal(ciphertext, chunk, nonce, payload_key);

    // Compute payload hash.
    const payload_hash = computePayloadHash(version, header_hash, nonce, ciphertext, is_final);

    // Compute per-receiver authenticators.
    const authenticators = try allocator.alloc(types.PayloadAuthenticator, mac_keys.len);
    defer allocator.free(authenticators);
    for (mac_keys, 0..) |mk, i| {
        authenticators[i] = computePayloadAuthenticator(mk, payload_hash);
    }

    // Encode the block.
    switch (version.major) {
        1 => try encodeEncryptionBlockV1(allocator, output, authenticators, ciphertext),
        2 => try encodeEncryptionBlockV2(allocator, output, authenticators, ciphertext, is_final),
        else => return sp_errors.Error.BadVersion,
    }
}

// ---------------------------------------------------------------------------
// MAC key computation
// ---------------------------------------------------------------------------

/// Compute MAC keys for each receiver (sender-side).
pub fn computeMacKeysSender(
    allocator: Allocator,
    version: types.Version,
    sender: key_mod.BoxSecretKey,
    ephemeral: key_mod.BoxSecretKey,
    receivers: []const key_mod.BoxPublicKey,
    header_hash: types.HeaderHash,
) ![]types.MacKey {
    const mac_keys = try allocator.alloc(types.MacKey, receivers.len);
    errdefer allocator.free(mac_keys);

    for (receivers, 0..) |recv_pk, i| {
        mac_keys[i] = switch (version.major) {
            1 => try computeMacKeySingleDH(
                sender,
                recv_pk,
                try nonce_mod.macKeyNonce(version, header_hash, i, false),
            ),
            2 => try computeMacKeyV2(
                sender,
                ephemeral,
                recv_pk,
                header_hash,
                i,
            ),
            else => return sp_errors.Error.BadVersion,
        };
    }
    return mac_keys;
}

/// Compute a MAC key from a single DH operation.
/// Box(secret, public, nonce, 32_zero_bytes) -> take bytes [tag_len:tag_len+32] of output.
fn computeMacKeySingleDH(
    secret: key_mod.BoxSecretKey,
    public: key_mod.BoxPublicKey,
    nonce: types.Nonce,
) !types.MacKey {
    const zeros = [_]u8{0} ** 32;
    var shared_key = NaclBox.createSharedSecret(public.bytes, secret.bytes) catch {
        return sp_errors.Error.BadEphemeralKey;
    };
    // Fix 1 (C1): Zero shared key after use.
    defer std.crypto.secureZero(u8, &shared_key);
    var sealed: [32 + secretbox_tag_length]u8 = undefined;
    // Fix 1 (C1): Zero sealed buffer after use.
    defer std.crypto.secureZero(u8, &sealed);
    SecretBox.seal(&sealed, &zeros, nonce, shared_key);
    // The ciphertext after the tag is the MAC key.
    return sealed[secretbox_tag_length..].*;
}

/// Compute V2 MAC key: combine sender-based and ephemeral-based MACs via SHA-512.
fn computeMacKeyV2(
    sender_or_receiver: key_mod.BoxSecretKey,
    ephemeral_or_sender_pk: key_mod.BoxSecretKey,
    counterpart_pk: key_mod.BoxPublicKey,
    header_hash: types.HeaderHash,
    recipient_index: usize,
) !types.MacKey {
    var mac_sender = try computeMacKeySingleDH(
        sender_or_receiver,
        counterpart_pk,
        try nonce_mod.macKeyNonce(types.Version.v2(), header_hash, recipient_index, false),
    );
    // Fix 1 (C1): Zero mac_sender after use.
    defer std.crypto.secureZero(u8, &mac_sender);
    var mac_ephemeral = try computeMacKeySingleDH(
        ephemeral_or_sender_pk,
        counterpart_pk,
        try nonce_mod.macKeyNonce(types.Version.v2(), header_hash, recipient_index, true),
    );
    // Fix 1 (C1): Zero mac_ephemeral after use.
    defer std.crypto.secureZero(u8, &mac_ephemeral);

    // SHA-512(sender_mac || ephemeral_mac) truncated to 32 bytes.
    var combined: [64]u8 = undefined;
    // Fix 1 (C1): Zero combined hash after use.
    defer std.crypto.secureZero(u8, &combined);
    @memcpy(combined[0..32], &mac_sender);
    @memcpy(combined[32..64], &mac_ephemeral);

    var hash: [64]u8 = undefined;
    // Fix: Zero the SHA-512 hash after use (matches receiver-side pattern).
    defer std.crypto.secureZero(u8, &hash);
    Sha512.hash(&combined, &hash, .{});
    return hash[0..32].*;
}

/// Compute MAC key from the receiver's perspective (for decryption).
/// For V1: single DH(receiver_sk, sender_pk).
/// For V2: SHA-512(DH(receiver_sk, sender_pk) || DH(receiver_sk, ephemeral_pk))[0:32].
pub fn computeMacKeyReceiver(
    version: types.Version,
    receiver: key_mod.BoxSecretKey,
    sender_pk: key_mod.BoxPublicKey,
    ephemeral_pk: key_mod.BoxPublicKey,
    header_hash: types.HeaderHash,
    recipient_index: usize,
) !types.MacKey {
    return switch (version.major) {
        1 => try computeMacKeySingleDH(
            receiver,
            sender_pk,
            try nonce_mod.macKeyNonce(version, header_hash, recipient_index, false),
        ),
        2 => blk: {
            var mac_sender = try computeMacKeySingleDH(
                receiver,
                sender_pk,
                try nonce_mod.macKeyNonce(types.Version.v2(), header_hash, recipient_index, false),
            );
            defer std.crypto.secureZero(u8, &mac_sender);
            var mac_ephemeral = try computeMacKeySingleDH(
                receiver,
                ephemeral_pk,
                try nonce_mod.macKeyNonce(types.Version.v2(), header_hash, recipient_index, true),
            );
            defer std.crypto.secureZero(u8, &mac_ephemeral);

            var combined: [64]u8 = undefined;
            defer std.crypto.secureZero(u8, &combined);
            @memcpy(combined[0..32], &mac_sender);
            @memcpy(combined[32..64], &mac_ephemeral);

            var hash: [64]u8 = undefined;
            defer std.crypto.secureZero(u8, &hash);
            Sha512.hash(&combined, &hash, .{});
            break :blk hash[0..32].*;
        },
        else => sp_errors.Error.BadVersion,
    };
}

// ---------------------------------------------------------------------------
// Payload hash and authenticator (pub for use by decrypt.zig)
// ---------------------------------------------------------------------------

/// Compute the hash that is authenticated for each payload block.
/// SHA-512(headerHash || nonce || [isFinalByte for v2] || ciphertext)
pub fn computePayloadHash(
    version: types.Version,
    header_hash: types.HeaderHash,
    nonce: types.Nonce,
    ciphertext: []const u8,
    is_final: bool,
) [64]u8 {
    var hasher = Sha512.init(.{});
    hasher.update(&header_hash);
    hasher.update(&nonce);
    if (version.major == 2) {
        const final_byte: [1]u8 = .{if (is_final) 1 else 0};
        hasher.update(&final_byte);
    }
    hasher.update(ciphertext);
    return hasher.finalResult();
}

/// Compute the per-receiver authenticator for a block.
/// HMAC-SHA512(mac_key, payload_hash)[0:32]
pub fn computePayloadAuthenticator(mac_key: types.MacKey, payload_hash: [64]u8) types.PayloadAuthenticator {
    var hmac = HmacSha512.init(&mac_key);
    hmac.update(&payload_hash);
    var full_mac: [64]u8 = undefined;
    defer std.crypto.secureZero(u8, &full_mac);
    hmac.final(&full_mac);
    return full_mac[0..32].*;
}

// ---------------------------------------------------------------------------
// Msgpack encoding helpers
// ---------------------------------------------------------------------------

fn encodeEncryptionBlockV1(
    allocator: Allocator,
    output: *std.ArrayList(u8),
    authenticators: []const types.PayloadAuthenticator,
    ciphertext: []const u8,
) !void {
    // V1: [authenticators_array, ciphertext]
    var arr = try Payload.arrPayload(2, allocator);
    errdefer arr.free(allocator);

    var auth_arr = try Payload.arrPayload(authenticators.len, allocator);
    for (authenticators, 0..) |auth, i| {
        const auth_payload = try Payload.binToPayload(&auth, allocator);
        try auth_arr.setArrElement(i, auth_payload);
    }
    try arr.setArrElement(0, auth_arr);

    const ct_payload = try Payload.binToPayload(ciphertext, allocator);
    try arr.setArrElement(1, ct_payload);

    try writePayload(allocator, output, arr);
}

fn encodeEncryptionBlockV2(
    allocator: Allocator,
    output: *std.ArrayList(u8),
    authenticators: []const types.PayloadAuthenticator,
    ciphertext: []const u8,
    is_final: bool,
) !void {
    // V2: [is_final, authenticators_array, ciphertext]
    var arr = try Payload.arrPayload(3, allocator);
    errdefer arr.free(allocator);

    try arr.setArrElement(0, Payload.boolToPayload(is_final));

    var auth_arr = try Payload.arrPayload(authenticators.len, allocator);
    for (authenticators, 0..) |auth, i| {
        const auth_payload = try Payload.binToPayload(&auth, allocator);
        try auth_arr.setArrElement(i, auth_payload);
    }
    try arr.setArrElement(1, auth_arr);

    const ct_payload = try Payload.binToPayload(ciphertext, allocator);
    try arr.setArrElement(2, ct_payload);

    try writePayload(allocator, output, arr);
}

// Fix 3 (C6): Replace stack buffer with heap allocation in writePayload.
fn writePayload(allocator: Allocator, output: *std.ArrayList(u8), payload: Payload) !void {
    const buf_size = 2 * types.encryption_block_size + 4096;
    try mp_utils.writePayload(allocator, output, payload, buf_size);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "seal V2 empty message single receiver" {
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();

    const receiver_pks = [_]key_mod.BoxPublicKey{receiver_kp.public_key};
    const result = try seal(allocator, &[_]u8{}, sender_kp.secret_key, &receiver_pks, .{});
    defer allocator.free(result);

    // Even an empty message must produce a header + at least one payload block.
    // A minimal header is well over 100 bytes (format name, version, ephemeral key,
    // sender secretbox, receiver list). Check that the output is substantial.
    try std.testing.expect(result.len > 100);
    // The first byte should be a valid msgpack bin format header:
    // 0xC4 = bin8, 0xC5 = bin16, 0xC6 = bin32 (the double-encoded header).
    try std.testing.expect(result[0] == 0xC4 or result[0] == 0xC5 or result[0] == 0xC6);
}

test "seal V2 short message" {
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();

    const msg = "hello saltpack encryption!";
    const receiver_pks = [_]key_mod.BoxPublicKey{receiver_kp.public_key};
    const result = try seal(allocator, msg, sender_kp.secret_key, &receiver_pks, .{});
    defer allocator.free(result);

    try std.testing.expect(result.len > msg.len);
    // Verify output starts with valid msgpack bin header (double-encoded header).
    try std.testing.expect(result[0] == 0xC4 or result[0] == 0xC5 or result[0] == 0xC6);
}

test "seal V1 short message" {
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();

    const msg = "hello v1 encryption";
    const receiver_pks = [_]key_mod.BoxPublicKey{receiver_kp.public_key};
    const result = try seal(allocator, msg, sender_kp.secret_key, &receiver_pks, .{ .version = types.Version.v1() });
    defer allocator.free(result);

    try std.testing.expect(result.len > msg.len);
    // Verify output starts with valid msgpack bin header (double-encoded header).
    try std.testing.expect(result[0] == 0xC4 or result[0] == 0xC5 or result[0] == 0xC6);
}

test "seal anonymous sender" {
    const allocator = std.testing.allocator;
    const receiver_kp = key_mod.BoxKeyPair.generate();

    const msg = "anonymous message";
    const receiver_pks = [_]key_mod.BoxPublicKey{receiver_kp.public_key};
    const result = try seal(allocator, msg, null, &receiver_pks, .{});
    defer allocator.free(result);

    try std.testing.expect(result.len > msg.len);
    // Verify output starts with valid msgpack bin header (double-encoded header).
    try std.testing.expect(result[0] == 0xC4 or result[0] == 0xC5 or result[0] == 0xC6);
}

test "seal multiple receivers" {
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const r1 = key_mod.BoxKeyPair.generate();
    const r2 = key_mod.BoxKeyPair.generate();
    const r3 = key_mod.BoxKeyPair.generate();

    const msg = "multi recipient test";
    const receiver_pks = [_]key_mod.BoxPublicKey{ r1.public_key, r2.public_key, r3.public_key };
    const result = try seal(allocator, msg, sender_kp.secret_key, &receiver_pks, .{});
    defer allocator.free(result);

    try std.testing.expect(result.len > msg.len);
    // Verify output starts with valid msgpack bin header (double-encoded header).
    try std.testing.expect(result[0] == 0xC4 or result[0] == 0xC5 or result[0] == 0xC6);
}

test "seal rejects zero receivers" {
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const empty_pks = [_]key_mod.BoxPublicKey{};
    try std.testing.expectError(sp_errors.Error.BadReceivers, seal(allocator, "test", sender_kp.secret_key, &empty_pks, .{}));
}

test "seal rejects duplicate receivers" {
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();

    const receiver_pks = [_]key_mod.BoxPublicKey{ receiver_kp.public_key, receiver_kp.public_key };
    try std.testing.expectError(sp_errors.Error.RepeatedKey, seal(allocator, "test", sender_kp.secret_key, &receiver_pks, .{}));
}

test "seal with hide_identity" {
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();

    const msg = "hidden identity test";
    var hidden_pk = receiver_kp.public_key;
    hidden_pk.hide_identity = true;
    const receiver_pks = [_]key_mod.BoxPublicKey{hidden_pk};
    const result = try seal(allocator, msg, sender_kp.secret_key, &receiver_pks, .{});
    defer allocator.free(result);

    // Output must be larger than the plaintext (header overhead + encryption overhead).
    try std.testing.expect(result.len > msg.len);
    // Output must exceed a minimum header overhead threshold.
    try std.testing.expect(result.len > 100);
    // The first byte should be a valid msgpack bin format header (double-encoded header).
    try std.testing.expect(result[0] == 0xC4 or result[0] == 0xC5 or result[0] == 0xC6);
}

test "computePayloadHash V2 includes final flag" {
    const hh = [_]u8{0xAA} ** 64;
    const nonce = [_]u8{0xBB} ** 24;
    const ct = "test ciphertext";

    const hash_nonfinal = computePayloadHash(types.Version.v2(), hh, nonce, ct, false);
    const hash_final = computePayloadHash(types.Version.v2(), hh, nonce, ct, true);

    try std.testing.expect(!std.mem.eql(u8, &hash_nonfinal, &hash_final));
}

test "computePayloadHash V1 ignores final flag" {
    const hh = [_]u8{0xAA} ** 64;
    const nonce = [_]u8{0xBB} ** 24;
    const ct = "test ciphertext";

    const hash_nonfinal = computePayloadHash(types.Version.v1(), hh, nonce, ct, false);
    const hash_final = computePayloadHash(types.Version.v1(), hh, nonce, ct, true);

    try std.testing.expectEqualSlices(u8, &hash_nonfinal, &hash_final);
}

test "computePayloadAuthenticator deterministic" {
    const mac_key = [_]u8{0xCC} ** 32;
    const payload_hash = [_]u8{0xDD} ** 64;

    const auth1 = computePayloadAuthenticator(mac_key, payload_hash);
    const auth2 = computePayloadAuthenticator(mac_key, payload_hash);

    try std.testing.expectEqualSlices(u8, &auth1, &auth2);
}

test "computePayloadAuthenticator differs for different keys" {
    const key1 = [_]u8{0x01} ** 32;
    const key2 = [_]u8{0x02} ** 32;
    const payload_hash = [_]u8{0xDD} ** 64;

    const auth1 = computePayloadAuthenticator(key1, payload_hash);
    const auth2 = computePayloadAuthenticator(key2, payload_hash);

    try std.testing.expect(!std.mem.eql(u8, &auth1, &auth2));
}

test "seal rejects bad version (major=3)" {
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();

    const receiver_pks = [_]key_mod.BoxPublicKey{receiver_kp.public_key};
    try std.testing.expectError(sp_errors.Error.BadVersion, seal(allocator, "test", sender_kp.secret_key, &receiver_pks, .{ .version = .{ .major = 3, .minor = 0 } }));
}
