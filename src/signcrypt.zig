//! Saltpack signcryption (mode 3): combined signing + encryption.
//!
//! Implements the saltpack signcryption protocol, which provides both
//! authentication (via Ed25519 signatures) and confidentiality (via
//! NaCl SecretBox) in a single operation. Supports anonymous senders
//! and both Box (DH) and symmetric key recipients.

const std = @import("std");
const types = @import("types.zig");
const sp_errors = @import("errors.zig");
const key = @import("key.zig");
const nonce_mod = @import("nonce.zig");
const header_mod = @import("header.zig");

const Allocator = std.mem.Allocator;
const Sha512 = std.crypto.hash.sha2.Sha512;
const HmacSha512 = std.crypto.auth.hmac.sha2.HmacSha512;
const SecretBox = std.crypto.nacl.SecretBox;
const NaclBox = std.crypto.nacl.Box;
const secureZero = std.crypto.secureZero;

const mp_utils = @import("msgpack_utils.zig");
const MsgPack = mp_utils.MsgPack;
const BufferStream = mp_utils.BufferStream;
const fixedBufferStream = mp_utils.fixedBufferStream;
const Payload = mp_utils.Payload;

/// The Poly1305 tag length used by XSalsa20Poly1305 (16 bytes).
const secretbox_tag_length = SecretBox.tag_length;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// A symmetric key paired with an identifier, for use as a signcryption recipient.
pub const ReceiverSymmetricKey = struct {
    symmetric_key: types.SymmetricKey,
    identifier: []const u8,
};

/// Options for the signcryption seal operation.
pub const SealOptions = struct {
    /// Receiver box public keys (DH recipients).
    receiver_box_keys: []const key.BoxPublicKey = &.{},
    /// Receiver symmetric keys.
    receiver_symmetric_keys: []const ReceiverSymmetricKey = &.{},
};

/// Options for the signcryption open operation.
pub const OpenOptions = struct {
    /// Receiver symmetric keys for symmetric-key recipients.
    receiver_symmetric_keys: []const ReceiverSymmetricKey = &.{},
};

/// Result from opening a signcrypted message.
pub const OpenResult = struct {
    /// The decrypted plaintext.
    plaintext: []u8,
    /// Information about the sender. If sender_key is null and sender_is_anonymous
    /// is true, the sender chose to remain anonymous.
    key_info: sp_errors.MessageKeyInfo,
    allocator: Allocator,

    pub fn deinit(self: *const OpenResult) void {
        secureZero(u8, @constCast(self.plaintext));
        self.allocator.free(self.plaintext);
    }
};

// ---------------------------------------------------------------------------
// Seal (encrypt + sign)
// ---------------------------------------------------------------------------

/// Signcrypt-seal a plaintext message.
///
/// `sender_signing_key` may be null for anonymous sender mode.
/// At least one recipient (box or symmetric) must be provided.
pub fn seal(
    allocator: Allocator,
    plaintext: []const u8,
    sender_signing_key: ?key.SigningSecretKey,
    opts: SealOptions,
) ![]u8 {
    const total_receivers = opts.receiver_box_keys.len + opts.receiver_symmetric_keys.len;
    if (total_receivers == 0) return sp_errors.Error.BadReceivers;

    // Check for duplicate box receiver keys (matching encrypt.zig's pattern).
    for (opts.receiver_box_keys, 0..) |r1, i| {
        for (opts.receiver_box_keys[i + 1 ..]) |r2| {
            if (std.crypto.timing_safe.eql([32]u8, r1.bytes, r2.bytes)) {
                return sp_errors.Error.RepeatedKey;
            }
        }
    }

    // Generate ephemeral Box key pair.
    var ephemeral_kp = key.BoxKeyPair.generate();
    defer secureZero(u8, &ephemeral_kp.secret_key.bytes);

    // Generate random payload key.
    var payload_key: types.SymmetricKey = undefined;
    std.crypto.random.bytes(&payload_key);
    defer secureZero(u8, &payload_key);

    // Build receiver keys list.
    // We need to allocate both the ReceiverKeys array AND persist the payload_key_box
    // ciphertexts since ReceiverKeys stores slices.
    const receiver_keys = try allocator.alloc(header_mod.ReceiverKeys, total_receivers);
    defer allocator.free(receiver_keys);

    // Allocate storage for payload key boxes (each is 32 + 16 = 48 bytes).
    const pkb_len = 32 + secretbox_tag_length;
    const pkb_storage = try allocator.alloc(u8, total_receivers * pkb_len);
    defer allocator.free(pkb_storage);

    // Allocate persistent storage for receiver key identifiers (32 bytes each).
    // Each identifier is derived during the loop and must outlive the loop body
    // because ReceiverKeys.recipient_kid stores a slice into this buffer.
    const kid_storage = try allocator.alloc([32]u8, total_receivers);
    defer allocator.free(kid_storage);

    // (C2) Build a shuffled index mapping for receiver privacy.
    // This prevents leaking recipient type (box vs. symmetric) through ordering.
    const indices = try allocator.alloc(usize, total_receivers);
    defer allocator.free(indices);
    for (indices, 0..) |*idx, i| idx.* = i;
    if (indices.len > 1) {
        var si: usize = indices.len - 1;
        while (si > 0) : (si -= 1) {
            const j = std.crypto.random.intRangeLessThan(usize, 0, si + 1);
            std.mem.swap(usize, &indices[si], &indices[j]);
        }
    }

    // Build receiver keys in shuffled order. Each shuffled position `slot`
    // maps to an original receiver index `orig`. The nonce and KID are derived
    // using the slot position (the position in the header), matching the Go
    // reference where nonces are based on the final receiver list index.
    for (indices, 0..) |orig, slot| {
        if (orig < opts.receiver_box_keys.len) {
            // Box recipient.
            const recipient_pk = opts.receiver_box_keys[orig];
            var derived_key = try derivedEphemeralKeyFromBoxKeys(recipient_pk, ephemeral_kp.secret_key);
            defer secureZero(u8, &derived_key);
            kid_storage[slot] = try keyIdentifierFromDerivedKey(derived_key, slot);
            const recv_nonce = try nonce_mod.payloadKeyBoxNonce(types.Version.v2(), slot);

            const pkb_slice = pkb_storage[slot * pkb_len .. (slot + 1) * pkb_len];
            try secretBoxSeal(pkb_slice, &payload_key, recv_nonce, derived_key);

            receiver_keys[slot] = .{
                .recipient_kid = &kid_storage[slot],
                .payload_key_box = pkb_slice,
            };
        } else {
            // Symmetric recipient.
            const sym_idx = orig - opts.receiver_box_keys.len;
            const sym_rcv = opts.receiver_symmetric_keys[sym_idx];
            var derived_key = derivedKeyFromSymmetricKey(sym_rcv.symmetric_key, ephemeral_kp.public_key);
            defer secureZero(u8, &derived_key);
            const recv_nonce = try nonce_mod.payloadKeyBoxNonce(types.Version.v2(), slot);

            const pkb_slice = pkb_storage[slot * pkb_len .. (slot + 1) * pkb_len];
            try secretBoxSeal(pkb_slice, &payload_key, recv_nonce, derived_key);

            // (M12) For symmetric recipients, the identifier is supplied by the
            // caller and passed raw as the KID, matching Go's behavior where
            // ReceiverKID is set to r.Identifier (variable-length []byte).
            receiver_keys[slot] = .{
                .recipient_kid = sym_rcv.identifier,
                .payload_key_box = pkb_slice,
            };
        }
    }

    // Encrypt sender signing public key (or zeros for anonymous).
    const sender_key_nonce = nonce_mod.senderKeyNonce();
    var sender_pk_bytes: [32]u8 = [_]u8{0} ** 32;
    if (sender_signing_key) |ssk| {
        sender_pk_bytes = ssk.getPublicKey().bytes;
    }
    var sender_secretbox: [32 + secretbox_tag_length]u8 = undefined;
    try secretBoxSeal(&sender_secretbox, &sender_pk_bytes, sender_key_nonce, payload_key);

    // Build and encode header.
    const enc_header = header_mod.EncryptionHeader{
        .version = types.Version.v2(),
        .message_type = .signcryption,
        .ephemeral_key = ephemeral_kp.public_key.bytes,
        .sender_secretbox = &sender_secretbox,
        .receivers = receiver_keys,
    };

    const header_result = try header_mod.encodeEncryptionHeader(allocator, enc_header);
    defer allocator.free(header_result.encoded);
    const header_hash = header_result.header_hash;

    // Build output buffer. Start with header.
    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);
    const estimated_size = plaintext.len + 4096; // plaintext + overhead
    try output.ensureTotalCapacity(allocator, estimated_size);
    try output.appendSlice(allocator, header_result.encoded);

    // Chunk plaintext and encrypt each block.
    const block_size = types.encryption_block_size;
    var block_number: u64 = 0;
    var offset: usize = 0;

    while (true) {
        if (block_number >= types.max_block_number) return sp_errors.Error.PacketOverflow;
        const remaining = plaintext.len - offset;
        const is_final = remaining <= block_size;
        const chunk_len = if (is_final) remaining else block_size;
        const chunk = plaintext[offset .. offset + chunk_len];

        // Compute signature or zeros (anonymous).
        var sig_bytes: [64]u8 = [_]u8{0} ** 64;
        if (sender_signing_key) |ssk| {
            const sig_input = computeSigncryptionSignatureInput(header_hash, block_number, is_final, chunk);
            sig_bytes = try ssk.sign(&sig_input);
        }

        // Build attached signature: signature(64) || plaintext_chunk.
        const attached_len = 64 + chunk_len;
        const attached = try allocator.alloc(u8, attached_len);
        defer allocator.free(attached);
        @memcpy(attached[0..64], &sig_bytes);
        @memcpy(attached[64..attached_len], chunk);

        // Encrypt with SecretBox.
        const chunk_nonce = nonce_mod.signcryptPayloadNonce(header_hash, block_number, is_final);
        const ct_len = attached_len + secretbox_tag_length;
        const ciphertext = try allocator.alloc(u8, ct_len);
        defer allocator.free(ciphertext);
        try secretBoxSeal(ciphertext, attached, chunk_nonce, payload_key);

        // Encode payload packet: [PayloadCiphertext, IsFinal]
        const packet = try encodeSigncryptionBlock(allocator, ciphertext, is_final);
        defer allocator.free(packet);
        try output.appendSlice(allocator, packet);

        block_number += 1;
        offset += chunk_len;

        if (is_final) break;
    }

    return try output.toOwnedSlice(allocator);
}

// ---------------------------------------------------------------------------
// Open (decrypt + verify)
// ---------------------------------------------------------------------------

/// Open a signcrypted message.
///
/// Returns the decrypted plaintext and information about the sender/recipient.
/// The caller owns the returned plaintext slice and must free it.
/// `open_opts` provides optional symmetric keys for symmetric-key recipients.
pub fn open(
    allocator: Allocator,
    ciphertext: []const u8,
    keyring: []const key.BoxKeyPair,
    signing_key_lookup: ?*const fn ([32]u8) ?key.SigningPublicKey,
    open_opts: OpenOptions,
) !OpenResult {
    if (ciphertext.len == 0) return sp_errors.Error.FailedToReadHeaderBytes;

    // Decode header.
    const header_decode_result = try decodeHeaderFromStream(allocator, ciphertext);
    const header_bytes_len = header_decode_result.bytes_consumed;
    const header_hash = header_decode_result.header_hash;
    const enc_header = header_decode_result.header;
    defer {
        allocator.free(enc_header.sender_secretbox);
        header_mod.freeDecodedReceivers(allocator, enc_header.receivers);
    }

    // Validate version and message type.
    if (enc_header.version.major != 2) return sp_errors.Error.BadVersion;
    if (enc_header.message_type != .signcryption) return sp_errors.Error.WrongMessageType;

    // (C9) Try to decrypt the payload key using box keys first, then symmetric keys.
    var payload_key = try tryDecryptPayloadKey(enc_header, keyring) orelse
        try tryDecryptPayloadKeySymmetric(enc_header, open_opts.receiver_symmetric_keys) orelse
        return sp_errors.Error.NoDecryptionKey;
    defer secureZero(u8, &payload_key);

    // Decrypt sender signing public key.
    const sender_key_nonce = nonce_mod.senderKeyNonce();
    var sender_pk_bytes: [32]u8 = undefined;
    defer secureZero(u8, &sender_pk_bytes);
    secretBoxOpen(&sender_pk_bytes, enc_header.sender_secretbox, sender_key_nonce, payload_key) catch {
        return sp_errors.Error.DecryptionFailed;
    };

    // Check if sender is anonymous (all zeros).
    const zero_key = [_]u8{0} ** 32;
    const sender_anonymous = std.crypto.timing_safe.eql([32]u8, sender_pk_bytes, zero_key);

    var sender_signing_pk: ?key.SigningPublicKey = null;
    if (!sender_anonymous) {
        // Look up the signing public key.
        if (signing_key_lookup) |lookup_fn| {
            sender_signing_pk = lookup_fn(sender_pk_bytes);
        }
        if (sender_signing_pk == null) {
            return sp_errors.Error.NoSenderKey;
        }
    }

    // Process payload blocks.
    var plaintext_buf: std.ArrayList(u8) = .empty;
    errdefer plaintext_buf.deinit(allocator);
    try plaintext_buf.ensureTotalCapacity(allocator, ciphertext.len);

    var remaining_data = ciphertext[header_bytes_len..];
    var block_number: u64 = 0;
    var saw_final = false;

    while (remaining_data.len > 0) {
        if (block_number >= types.max_block_number) return sp_errors.Error.PacketOverflow;
        const block_result = decodeSigncryptionBlock(allocator, remaining_data) catch {
            if (block_number == 0 and !saw_final) {
                return sp_errors.Error.TruncatedMessage;
            }
            return sp_errors.Error.BadCiphertext;
        };
        const block_ciphertext = block_result.ciphertext;
        const is_final = block_result.is_final;
        defer allocator.free(block_ciphertext);
        remaining_data = remaining_data[block_result.bytes_consumed..];

        if (block_ciphertext.len < secretbox_tag_length + 64) {
            return sp_errors.Error.DecryptionFailed;
        }

        // Decrypt the block.
        const chunk_nonce = nonce_mod.signcryptPayloadNonce(header_hash, block_number, is_final);
        const decrypted_len = block_ciphertext.len - secretbox_tag_length;
        const decrypted = try allocator.alloc(u8, decrypted_len);
        defer {
            secureZero(u8, decrypted);
            allocator.free(decrypted);
        }

        secretBoxOpen(decrypted, block_ciphertext, chunk_nonce, payload_key) catch {
            return sp_errors.Error.DecryptionFailed;
        };

        // Must have at least 64 bytes for the signature.
        if (decrypted.len < 64) {
            return sp_errors.Error.DecryptionFailed;
        }

        const sig_bytes: [64]u8 = decrypted[0..64].*;
        const chunk_plaintext = decrypted[64..];

        if (sender_anonymous) {
            // Per the saltpack spec, when the sender is anonymous the
            // signature bytes must be 64 zero bytes.
            const zero_sig = [_]u8{0} ** 64;
            if (!std.crypto.timing_safe.eql([64]u8, sig_bytes, zero_sig)) {
                return sp_errors.Error.DecryptionFailed;
            }
        } else {
            if (sender_signing_pk) |spk| {
                const sig_input = computeSigncryptionSignatureInput(header_hash, block_number, is_final, chunk_plaintext);
                spk.verify(&sig_input, sig_bytes) catch {
                    return sp_errors.Error.DecryptionFailed;
                };
            }
        }

        try plaintext_buf.appendSlice(allocator, chunk_plaintext);

        block_number += 1;

        if (is_final) {
            saw_final = true;
            break;
        }
    }

    if (!saw_final) {
        return sp_errors.Error.TruncatedMessage;
    }

    // (C4) Check for trailing data after the final block.
    if (remaining_data.len > 0) return sp_errors.Error.TrailingGarbage;

    var key_info = sp_errors.MessageKeyInfo{
        .num_recipients = enc_header.receivers.len,
    };
    if (sender_anonymous) {
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
// Key derivation
// ---------------------------------------------------------------------------

/// Derive the per-recipient symmetric key from a DH shared secret (Box recipients).
///
/// Following the Go reference: encrypt 32 bytes of zeros using Box(ephemeral, recipient)
/// with the derived-key nonce. The last 32 bytes of the result are the derived key.
/// This is equivalent to computing the DH shared secret but using only the standard
/// NaCl Box interface.
fn derivedEphemeralKeyFromBoxKeys(recipient_pk: key.BoxPublicKey, ephemeral_sk: key.BoxSecretKey) !([32]u8) {
    const zeros = [_]u8{0} ** 32;
    const derived_nonce = nonce_mod.signcryptDerivedKeyNonce();

    // Use Box to encrypt 32 zeros: the resulting ciphertext (excluding tag) is the derived key.
    var sealed: [32 + secretbox_tag_length]u8 = undefined;
    defer secureZero(u8, &sealed);
    var shared_key = NaclBox.createSharedSecret(recipient_pk.bytes, ephemeral_sk.bytes) catch {
        return sp_errors.Error.BadEphemeralKey;
    };
    defer secureZero(u8, &shared_key);
    SecretBox.seal(&sealed, &zeros, derived_nonce, shared_key);
    // The ciphertext (after the tag) is the derived key.
    return sealed[secretbox_tag_length..].*;
}

/// Compute key identifier from derived key and recipient index.
/// identifier = HMAC-SHA512(key=signcryption_box_key_identifier_context, msg=derived_key || nonce)[0:32]
fn keyIdentifierFromDerivedKey(derived_key: [32]u8, recipient_index: usize) ![32]u8 {
    const context = types.signcryption_box_key_identifier_context;
    var hmac = HmacSha512.init(context);
    hmac.update(&derived_key);
    const recv_nonce = try nonce_mod.payloadKeyBoxNonce(types.Version.v2(), recipient_index);
    hmac.update(&recv_nonce);
    var full_mac: [64]u8 = undefined;
    hmac.final(&full_mac);
    defer secureZero(u8, &full_mac);
    return full_mac[0..32].*;
}

/// Derive the per-recipient symmetric key from a symmetric key (symmetric recipients).
/// derived_key = HMAC-SHA512(key=signcryption_symmetric_key_context, msg=ephemeral_pk || symmetric_key)[0:32]
fn derivedKeyFromSymmetricKey(symmetric_key: types.SymmetricKey, ephemeral_pk: key.BoxPublicKey) [32]u8 {
    const context = types.signcryption_symmetric_key_context;
    var hmac = HmacSha512.init(context);
    hmac.update(&ephemeral_pk.bytes);
    hmac.update(&symmetric_key);
    var full_mac: [64]u8 = undefined;
    hmac.final(&full_mac);
    defer secureZero(u8, &full_mac);
    return full_mac[0..32].*;
}

// ---------------------------------------------------------------------------
// Signature computation
// ---------------------------------------------------------------------------

/// The total length of the signature input.
const sig_input_len = types.signature_encrypted_string.len + 64 + 24 + 1 + 64;

/// Compute the signcryption signature input for a given block.
fn computeSigncryptionSignatureInput(
    header_hash: types.HeaderHash,
    block_number: u64,
    is_final: bool,
    chunk_plaintext: []const u8,
) [sig_input_len]u8 {
    const context_len = types.signature_encrypted_string.len;

    var result: [sig_input_len]u8 = undefined;
    var pos: usize = 0;

    // Context string: "saltpack encrypted signature\0"
    @memcpy(result[pos .. pos + context_len], types.signature_encrypted_string);
    pos += context_len;

    // Header hash (64 bytes).
    @memcpy(result[pos .. pos + 64], &header_hash);
    pos += 64;

    // Nonce (24 bytes).
    const chunk_nonce = nonce_mod.signcryptPayloadNonce(header_hash, block_number, is_final);
    @memcpy(result[pos .. pos + 24], &chunk_nonce);
    pos += 24;

    // Final flag byte.
    result[pos] = if (is_final) 0x01 else 0x00;
    pos += 1;

    // SHA-512 of plaintext chunk (64 bytes).
    var plaintext_hash: [64]u8 = undefined;
    Sha512.hash(chunk_plaintext, &plaintext_hash, .{});
    @memcpy(result[pos .. pos + 64], &plaintext_hash);

    return result;
}

// ---------------------------------------------------------------------------
// SecretBox helpers (runtime-length wrappers)
// ---------------------------------------------------------------------------

/// SecretBox seal: encrypt and authenticate msg, writing tag || ciphertext to out.
fn secretBoxSeal(out: []u8, msg: []const u8, nonce_val: [24]u8, key_val: [32]u8) sp_errors.Error!void {
    // (H2) Use proper error return instead of debug.assert so the check
    // is not elided in ReleaseFast mode.
    if (out.len != msg.len + secretbox_tag_length) return sp_errors.Error.BadCiphertext;
    SecretBox.seal(out, msg, nonce_val, key_val);
}

/// SecretBox open: verify and decrypt ciphertext (tag || encrypted), writing plaintext to out.
fn secretBoxOpen(out: []u8, ciphertext_with_tag: []const u8, nonce_val: [24]u8, key_val: [32]u8) !void {
    if (ciphertext_with_tag.len < secretbox_tag_length) return sp_errors.Error.BadCiphertext;
    // (H2) Use proper error return instead of debug.assert so the check
    // is not elided in ReleaseFast mode.
    if (out.len != ciphertext_with_tag.len - secretbox_tag_length) return sp_errors.Error.BadCiphertext;
    SecretBox.open(out, ciphertext_with_tag, nonce_val, key_val) catch {
        return sp_errors.Error.BadCiphertext;
    };
}

// ---------------------------------------------------------------------------
// Msgpack encoding/decoding helpers
// ---------------------------------------------------------------------------

/// Encode a signcryption block: [PayloadCiphertext, IsFinal]
fn encodeSigncryptionBlock(allocator: Allocator, ciphertext_data: []const u8, is_final: bool) ![]u8 {
    var arr = try Payload.arrPayload(2, allocator);
    errdefer arr.free(allocator);

    const ct_payload = try Payload.binToPayload(ciphertext_data, allocator);
    try arr.setArrElement(0, ct_payload);

    try arr.setArrElement(1, Payload.boolToPayload(is_final));

    const buf_size: usize = 1200000;
    return mp_utils.encodePayload(allocator, arr, buf_size);
}

/// Decode result for a signcryption block.
const BlockDecodeResult = struct {
    ciphertext: []u8,
    is_final: bool,
    bytes_consumed: usize,
};

/// Decode a signcryption block from a byte stream.
fn decodeSigncryptionBlock(allocator: Allocator, data: []const u8) !BlockDecodeResult {
    // Copy data into a heap buffer for the fixedBufferStream reader.
    const max_buf: usize = 1200000;
    const read_buf_storage = try allocator.alloc(u8, @min(data.len, max_buf));
    defer allocator.free(read_buf_storage);
    const copy_len = read_buf_storage.len;
    @memcpy(read_buf_storage[0..copy_len], data[0..copy_len]);
    var read_buf = fixedBufferStream(read_buf_storage);

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

    if (arr_items.len != 2) return sp_errors.Error.BadCiphertext;

    // Element 0: ciphertext (bin)
    const ct_bytes = switch (arr_items[0]) {
        .bin => |b| b.bin,
        else => return sp_errors.Error.BadCiphertext,
    };

    // Element 1: is_final (bool)
    const is_final = switch (arr_items[1]) {
        .bool => |b| b,
        else => return sp_errors.Error.BadCiphertext,
    };

    const ciphertext_out = try allocator.alloc(u8, ct_bytes.len);
    @memcpy(ciphertext_out, ct_bytes);

    return BlockDecodeResult{
        .ciphertext = ciphertext_out,
        .is_final = is_final,
        .bytes_consumed = read_buf.pos,
    };
}

/// Header decode result from a byte stream.
const HeaderDecodeResult = mp_utils.HeaderDecodeResult;

/// Decode the header from the front of a ciphertext byte stream.
fn decodeHeaderFromStream(allocator: Allocator, data: []const u8) !HeaderDecodeResult {
    return mp_utils.decodeHeaderFromStream(allocator, data);
}

/// Try to decrypt the payload key using the box secret keys in the keyring.
///
/// To prevent timing side-channels that could reveal which key slot belongs
/// to the recipient, this function always iterates ALL receiver slots even
/// after finding a match. Only the first successful result is kept.
fn tryDecryptPayloadKey(
    enc_header: header_mod.EncryptionHeader,
    keyring: []const key.BoxKeyPair,
) !?[32]u8 {
    const ephemeral_pk = key.BoxPublicKey.fromBytes(enc_header.ephemeral_key) catch {
        return sp_errors.Error.BadEphemeralKey;
    };
    var result: ?[32]u8 = null;

    for (keyring) |kp| {
        var derived_key = derivedEphemeralKeyFromBoxKeys(ephemeral_pk, kp.secret_key) catch continue;
        defer secureZero(u8, &derived_key);

        for (enc_header.receivers, 0..) |receiver, recv_idx| {
            const expected_id = try keyIdentifierFromDerivedKey(derived_key, recv_idx);

            if (receiver.recipient_kid) |kid| {
                if (kid.len == 32 and std.crypto.timing_safe.eql([32]u8, expected_id, kid[0..32].*)) {
                    // This is the right key. Decrypt the payload key box.
                    const recv_nonce = try nonce_mod.payloadKeyBoxNonce(types.Version.v2(), recv_idx);

                    if (receiver.payload_key_box.len < secretbox_tag_length) {
                        continue;
                    }

                    var payload_key: [32]u8 = undefined;
                    secretBoxOpen(&payload_key, receiver.payload_key_box, recv_nonce, derived_key) catch {
                        continue;
                    };

                    // Keep only the first match.
                    if (result == null) {
                        result = payload_key;
                    } else {
                        secureZero(u8, &payload_key);
                    }
                }
            }
        }
    }

    return result;
}

/// (C9) Try to decrypt the payload key using symmetric keys.
///
/// For each receiver slot in the header, check whether any of the provided
/// symmetric keys matches based on the key identifier (KID). If the KID
/// matches, derive a decryption key using `derivedKeyFromSymmetricKey` and
/// attempt to open the payload_key_box. Following the Go reference
/// (`signcrypt_open.go:trySharedSymmetricKeys`).
///
/// To prevent timing side-channels, this function always iterates ALL
/// receiver slots even after finding a match.
fn tryDecryptPayloadKeySymmetric(
    enc_header: header_mod.EncryptionHeader,
    symmetric_keys: []const ReceiverSymmetricKey,
) !?[32]u8 {
    if (symmetric_keys.len == 0) return null;

    const ephemeral_pk = key.BoxPublicKey.fromBytes(enc_header.ephemeral_key) catch {
        return sp_errors.Error.BadEphemeralKey;
    };
    var result: ?[32]u8 = null;

    for (enc_header.receivers, 0..) |receiver, recv_idx| {
        if (receiver.recipient_kid) |kid| {
            for (symmetric_keys) |sym_key| {
                // (M12) Compare the header's KID with the raw identifier
                // bytes from the symmetric key, matching Go's behavior
                // where ReceiverKID is the raw Identifier bytes.
                if (kid.len == sym_key.identifier.len and
                    std.mem.eql(u8, kid, sym_key.identifier))
                {
                    // Derive the decryption key from the symmetric key
                    // and ephemeral public key.
                    var derived_key = derivedKeyFromSymmetricKey(sym_key.symmetric_key, ephemeral_pk);
                    defer secureZero(u8, &derived_key);

                    const recv_nonce = try nonce_mod.payloadKeyBoxNonce(types.Version.v2(), recv_idx);

                    if (receiver.payload_key_box.len < secretbox_tag_length) {
                        continue;
                    }

                    var payload_key: [32]u8 = undefined;
                    secretBoxOpen(&payload_key, receiver.payload_key_box, recv_nonce, derived_key) catch {
                        continue;
                    };

                    // Keep only the first match.
                    if (result == null) {
                        result = payload_key;
                    } else {
                        secureZero(u8, &payload_key);
                    }
                }
            }
        }
    }

    return result;
}

// symmetricKidFromIdentifier has been removed. Per Go parity, symmetric
// receiver identifiers are passed raw as the ReceiverKID regardless of
// length. The seal() function stores sym_rcv.identifier directly and
// tryDecryptPayloadKeySymmetric() compares identifiers by raw byte equality.

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "signcrypt and open empty message" {
    const allocator = std.testing.allocator;
    const signing_kp = key.SigningKeyPair.generate();
    const box_kp = key.BoxKeyPair.generate();

    const receiver_box_keys = [_]key.BoxPublicKey{box_kp.public_key};

    const sealed = try seal(allocator, "", signing_kp.secret_key, .{
        .receiver_box_keys = &receiver_box_keys,
    });
    defer allocator.free(sealed);

    const keyring_keys = [_]key.BoxKeyPair{box_kp};
    const spk = signing_kp.secret_key.getPublicKey();
    const lookup = struct {
        fn lookupFn(pk_bytes: [32]u8) ?key.SigningPublicKey {
            return key.SigningPublicKey.fromBytes(pk_bytes) catch return null;
        }
    };

    const result = try open(allocator, sealed, &keyring_keys, &lookup.lookupFn, .{});
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 0), result.plaintext.len);
    try std.testing.expect(!result.key_info.sender_is_anonymous);
    try std.testing.expect(result.key_info.sender_key != null);
    try std.testing.expectEqualSlices(u8, &spk.bytes, &result.key_info.sender_key.?);
}

test "signcrypt and open short message" {
    const allocator = std.testing.allocator;
    const signing_kp = key.SigningKeyPair.generate();
    const box_kp = key.BoxKeyPair.generate();

    const msg = "hello world";
    const receiver_box_keys = [_]key.BoxPublicKey{box_kp.public_key};

    const sealed = try seal(allocator, msg, signing_kp.secret_key, .{
        .receiver_box_keys = &receiver_box_keys,
    });
    defer allocator.free(sealed);

    const keyring_keys = [_]key.BoxKeyPair{box_kp};
    const lookup = struct {
        fn lookupFn(pk_bytes: [32]u8) ?key.SigningPublicKey {
            return key.SigningPublicKey.fromBytes(pk_bytes) catch return null;
        }
    };

    const result = try open(allocator, sealed, &keyring_keys, &lookup.lookupFn, .{});
    defer result.deinit();

    try std.testing.expectEqualStrings(msg, result.plaintext);
    try std.testing.expect(!result.key_info.sender_is_anonymous);
}

test "signcrypt and open multi-block message" {
    const allocator = std.testing.allocator;
    const signing_kp = key.SigningKeyPair.generate();
    const box_kp = key.BoxKeyPair.generate();

    // 2 * block_size = 2 MiB message to force multiple blocks.
    const msg_len = types.encryption_block_size * 2;
    const msg = try allocator.alloc(u8, msg_len);
    defer allocator.free(msg);
    @memset(msg, 0x42);

    const receiver_box_keys = [_]key.BoxPublicKey{box_kp.public_key};

    const sealed = try seal(allocator, msg, signing_kp.secret_key, .{
        .receiver_box_keys = &receiver_box_keys,
    });
    defer allocator.free(sealed);

    const keyring_keys = [_]key.BoxKeyPair{box_kp};
    const lookup = struct {
        fn lookupFn(pk_bytes: [32]u8) ?key.SigningPublicKey {
            return key.SigningPublicKey.fromBytes(pk_bytes) catch return null;
        }
    };

    const result = try open(allocator, sealed, &keyring_keys, &lookup.lookupFn, .{});
    defer result.deinit();

    try std.testing.expectEqual(msg_len, result.plaintext.len);
    try std.testing.expectEqualSlices(u8, msg, result.plaintext);
}

test "signcrypt anonymous sender" {
    const allocator = std.testing.allocator;
    const box_kp = key.BoxKeyPair.generate();

    const msg = "anonymous message";
    const receiver_box_keys = [_]key.BoxPublicKey{box_kp.public_key};

    const sealed = try seal(allocator, msg, null, .{
        .receiver_box_keys = &receiver_box_keys,
    });
    defer allocator.free(sealed);

    const keyring_keys = [_]key.BoxKeyPair{box_kp};

    const result = try open(allocator, sealed, &keyring_keys, null, .{});
    defer result.deinit();

    try std.testing.expectEqualStrings(msg, result.plaintext);
    try std.testing.expect(result.key_info.sender_is_anonymous);
    try std.testing.expect(result.key_info.sender_key == null);
}

test "signcrypt tampered ciphertext fails" {
    const allocator = std.testing.allocator;
    const signing_kp = key.SigningKeyPair.generate();
    const box_kp = key.BoxKeyPair.generate();

    const msg = "tamper test";
    const receiver_box_keys = [_]key.BoxPublicKey{box_kp.public_key};

    const sealed = try seal(allocator, msg, signing_kp.secret_key, .{
        .receiver_box_keys = &receiver_box_keys,
    });
    defer allocator.free(sealed);

    // Flip the last byte of the ciphertext.
    sealed[sealed.len - 1] ^= 1;

    const keyring_keys = [_]key.BoxKeyPair{box_kp};
    const lookup = struct {
        fn lookupFn(pk_bytes: [32]u8) ?key.SigningPublicKey {
            return key.SigningPublicKey.fromBytes(pk_bytes) catch return null;
        }
    };

    const result = open(allocator, sealed, &keyring_keys, &lookup.lookupFn, .{});
    try std.testing.expectError(sp_errors.Error.DecryptionFailed, result);
}

test "signcrypt wrong recipient key fails" {
    const allocator = std.testing.allocator;
    const signing_kp = key.SigningKeyPair.generate();
    const box_kp = key.BoxKeyPair.generate();
    const wrong_kp = key.BoxKeyPair.generate();

    const msg = "wrong key test";
    const receiver_box_keys = [_]key.BoxPublicKey{box_kp.public_key};

    const sealed = try seal(allocator, msg, signing_kp.secret_key, .{
        .receiver_box_keys = &receiver_box_keys,
    });
    defer allocator.free(sealed);

    // Try to open with wrong key.
    const keyring_keys = [_]key.BoxKeyPair{wrong_kp};
    const lookup = struct {
        fn lookupFn(pk_bytes: [32]u8) ?key.SigningPublicKey {
            return key.SigningPublicKey.fromBytes(pk_bytes) catch return null;
        }
    };

    const result = open(allocator, sealed, &keyring_keys, &lookup.lookupFn, .{});
    try std.testing.expectError(sp_errors.Error.NoDecryptionKey, result);
}

test "signcrypt multiple box recipients" {
    const allocator = std.testing.allocator;
    const signing_kp = key.SigningKeyPair.generate();
    const box_kp1 = key.BoxKeyPair.generate();
    const box_kp2 = key.BoxKeyPair.generate();

    const msg = "multi recipient";
    const receiver_box_keys = [_]key.BoxPublicKey{ box_kp1.public_key, box_kp2.public_key };

    const sealed = try seal(allocator, msg, signing_kp.secret_key, .{
        .receiver_box_keys = &receiver_box_keys,
    });
    defer allocator.free(sealed);

    const lookup = struct {
        fn lookupFn(pk_bytes: [32]u8) ?key.SigningPublicKey {
            return key.SigningPublicKey.fromBytes(pk_bytes) catch return null;
        }
    };

    // Recipient 1 can open.
    {
        const keyring_keys = [_]key.BoxKeyPair{box_kp1};
        const result = try open(allocator, sealed, &keyring_keys, &lookup.lookupFn, .{});
        defer result.deinit();
        try std.testing.expectEqualStrings(msg, result.plaintext);
    }

    // Recipient 2 can open.
    {
        const keyring_keys = [_]key.BoxKeyPair{box_kp2};
        const result = try open(allocator, sealed, &keyring_keys, &lookup.lookupFn, .{});
        defer result.deinit();
        try std.testing.expectEqualStrings(msg, result.plaintext);
    }
}

test "signcrypt bad signature detected" {
    const allocator = std.testing.allocator;
    const signing_kp = key.SigningKeyPair.generate();
    const box_kp = key.BoxKeyPair.generate();

    const msg = "signature test";
    const receiver_box_keys = [_]key.BoxPublicKey{box_kp.public_key};

    const sealed = try seal(allocator, msg, signing_kp.secret_key, .{
        .receiver_box_keys = &receiver_box_keys,
    });
    defer allocator.free(sealed);

    const keyring_keys = [_]key.BoxKeyPair{box_kp};

    // Use a lookup that always returns a random wrong key.
    const lookup = struct {
        fn lookupFn(_: [32]u8) ?key.SigningPublicKey {
            const rnd = key.SigningKeyPair.generate();
            return rnd.public_key;
        }
    };

    const result = open(allocator, sealed, &keyring_keys, &lookup.lookupFn, .{});
    try std.testing.expectError(sp_errors.Error.DecryptionFailed, result);
}

test "signcrypt open empty ciphertext fails" {
    const allocator = std.testing.allocator;
    const keyring_keys = [_]key.BoxKeyPair{};
    const result = open(allocator, "", &keyring_keys, null, .{});
    try std.testing.expectError(sp_errors.Error.FailedToReadHeaderBytes, result);
}

test "signcrypt exact one block message" {
    const allocator = std.testing.allocator;
    const signing_kp = key.SigningKeyPair.generate();
    const box_kp = key.BoxKeyPair.generate();

    // Exactly one block size.
    const msg = try allocator.alloc(u8, types.encryption_block_size);
    defer allocator.free(msg);
    @memset(msg, 0xAB);

    const receiver_box_keys = [_]key.BoxPublicKey{box_kp.public_key};
    const sealed = try seal(allocator, msg, signing_kp.secret_key, .{
        .receiver_box_keys = &receiver_box_keys,
    });
    defer allocator.free(sealed);

    const keyring_keys = [_]key.BoxKeyPair{box_kp};
    const lookup = struct {
        fn lookupFn(pk_bytes: [32]u8) ?key.SigningPublicKey {
            return key.SigningPublicKey.fromBytes(pk_bytes) catch return null;
        }
    };

    const result = try open(allocator, sealed, &keyring_keys, &lookup.lookupFn, .{});
    defer result.deinit();

    try std.testing.expectEqual(types.encryption_block_size, result.plaintext.len);
    try std.testing.expectEqualSlices(u8, msg, result.plaintext);
}

test "signcrypt rejects zero receivers" {
    const allocator = std.testing.allocator;
    const signing_kp = key.SigningKeyPair.generate();
    const result = seal(allocator, "test", signing_kp.secret_key, .{});
    try std.testing.expectError(sp_errors.Error.BadReceivers, result);
}

test "signcrypt truncated message fails" {
    const allocator = std.testing.allocator;
    const signing_kp = key.SigningKeyPair.generate();
    const box_kp = key.BoxKeyPair.generate();

    const msg = "this message will be truncated after signcryption";
    const receiver_box_keys = [_]key.BoxPublicKey{box_kp.public_key};

    const sealed = try seal(allocator, msg, signing_kp.secret_key, .{
        .receiver_box_keys = &receiver_box_keys,
    });
    defer allocator.free(sealed);

    // Truncate drastically: keep only enough for a partial header (first 30 bytes).
    // This ensures the header decode itself fails, avoiding internal allocations.
    const truncated_len = 30;
    const truncated = try allocator.alloc(u8, truncated_len);
    defer allocator.free(truncated);
    @memcpy(truncated, sealed[0..truncated_len]);

    const keyring_keys = [_]key.BoxKeyPair{box_kp};
    const lookup = struct {
        fn lookupFn(pk_bytes: [32]u8) ?key.SigningPublicKey {
            return key.SigningPublicKey.fromBytes(pk_bytes) catch return null;
        }
    };

    const result = open(allocator, truncated, &keyring_keys, &lookup.lookupFn, .{});
    try std.testing.expect(std.meta.isError(result));
}

test "signcrypt open rejects encrypted message" {
    const allocator = std.testing.allocator;
    const encrypt_mod = @import("encrypt.zig");
    const sender_kp = key.BoxKeyPair.generate();
    const receiver_kp = key.BoxKeyPair.generate();

    const receiver_pks = [_]key.BoxPublicKey{receiver_kp.public_key};
    const ct = try encrypt_mod.seal(allocator, "hello", sender_kp.secret_key, &receiver_pks, .{});
    defer allocator.free(ct);

    const keyring_keys = [_]key.BoxKeyPair{receiver_kp};
    const lookup = struct {
        fn lookupFn(pk_bytes: [32]u8) ?key.SigningPublicKey {
            return key.SigningPublicKey.fromBytes(pk_bytes) catch return null;
        }
    };

    const result = open(allocator, ct, &keyring_keys, &lookup.lookupFn, .{});
    try std.testing.expectError(sp_errors.Error.WrongMessageType, result);
}

test "signcrypt open returns NoSenderKey when lookup returns null" {
    const allocator = std.testing.allocator;
    const signing_kp = key.SigningKeyPair.generate();
    const box_kp = key.BoxKeyPair.generate();

    const msg = "test no sender key";
    const receiver_box_keys = [_]key.BoxPublicKey{box_kp.public_key};

    const sealed = try seal(allocator, msg, signing_kp.secret_key, .{
        .receiver_box_keys = &receiver_box_keys,
    });
    defer allocator.free(sealed);

    const keyring_keys = [_]key.BoxKeyPair{box_kp};

    // Lookup that always returns null (sender key not found).
    const lookup = struct {
        fn lookupFn(_: [32]u8) ?key.SigningPublicKey {
            return null;
        }
    };

    const result = open(allocator, sealed, &keyring_keys, &lookup.lookupFn, .{});
    try std.testing.expectError(sp_errors.Error.NoSenderKey, result);
}

// ---------------------------------------------------------------------------
// Tests for C2: Signcryption receivers shuffled
// ---------------------------------------------------------------------------

test "signcrypt seal shuffles box and symmetric receivers (C2)" {
    // Seal the same message multiple times with both box and symmetric recipients.
    // Because the shuffle is random, the header receiver order should differ
    // across multiple seal() calls (with overwhelming probability for 4+ receivers).
    const allocator = std.testing.allocator;
    const signing_kp = key.SigningKeyPair.generate();
    const box_kp1 = key.BoxKeyPair.generate();
    const box_kp2 = key.BoxKeyPair.generate();

    const sym_key1: types.SymmetricKey = [_]u8{0xAA} ** 32;
    const sym_key2: types.SymmetricKey = [_]u8{0xBB} ** 32;
    const sym_rcvs = [_]ReceiverSymmetricKey{
        .{ .symmetric_key = sym_key1, .identifier = &([_]u8{0x01} ** 32) },
        .{ .symmetric_key = sym_key2, .identifier = &([_]u8{0x02} ** 32) },
    };

    const receiver_box_keys = [_]key.BoxPublicKey{ box_kp1.public_key, box_kp2.public_key };

    // Seal multiple times and check that at least one has a different KID order.
    // With 4 receivers and random shuffle, the probability of all 10 trials
    // producing the same order is (1/4!)^9 which is vanishingly small.
    var saw_different = false;
    var first_kid_order: ?[4][32]u8 = null;

    for (0..10) |_| {
        const sealed = try seal(allocator, "test", signing_kp.secret_key, .{
            .receiver_box_keys = &receiver_box_keys,
            .receiver_symmetric_keys = &sym_rcvs,
        });
        defer allocator.free(sealed);

        // Decode header to inspect receiver KIDs.
        const hdr_result = try decodeHeaderFromStream(allocator, sealed);
        const hdr = hdr_result.header;
        defer {
            allocator.free(hdr.sender_secretbox);
            header_mod.freeDecodedReceivers(allocator, hdr.receivers);
        }

        try std.testing.expectEqual(@as(usize, 4), hdr.receivers.len);

        var current_order: [4][32]u8 = undefined;
        for (hdr.receivers, 0..) |rcv, i| {
            const kid = rcv.recipient_kid.?;
            current_order[i] = kid[0..32].*;
        }

        if (first_kid_order) |first| {
            if (!std.mem.eql(u8, std.mem.asBytes(&first), std.mem.asBytes(&current_order))) {
                saw_different = true;
            }
        } else {
            first_kid_order = current_order;
        }
    }

    // At least one ordering should differ from the first.
    try std.testing.expect(saw_different);
}

// ---------------------------------------------------------------------------
// Tests for C4: Trailing garbage check
// ---------------------------------------------------------------------------

test "signcrypt open rejects trailing garbage after final block (C4)" {
    const allocator = std.testing.allocator;
    const signing_kp = key.SigningKeyPair.generate();
    const box_kp = key.BoxKeyPair.generate();

    const msg = "trailing garbage test";
    const receiver_box_keys = [_]key.BoxPublicKey{box_kp.public_key};

    const sealed = try seal(allocator, msg, signing_kp.secret_key, .{
        .receiver_box_keys = &receiver_box_keys,
    });
    defer allocator.free(sealed);

    // Append trailing garbage bytes after the valid message.
    const garbage = [_]u8{ 0xDE, 0xAD, 0xBE, 0xEF, 0x42 };
    const tampered = try allocator.alloc(u8, sealed.len + garbage.len);
    defer allocator.free(tampered);
    @memcpy(tampered[0..sealed.len], sealed);
    @memcpy(tampered[sealed.len..], &garbage);

    const keyring_keys = [_]key.BoxKeyPair{box_kp};
    const lookup = struct {
        fn lookupFn(pk_bytes: [32]u8) ?key.SigningPublicKey {
            return key.SigningPublicKey.fromBytes(pk_bytes) catch return null;
        }
    };

    const result = open(allocator, tampered, &keyring_keys, &lookup.lookupFn, .{});
    try std.testing.expectError(sp_errors.Error.TrailingGarbage, result);
}

// ---------------------------------------------------------------------------
// Tests for C9: Symmetric key signcrypt open
// ---------------------------------------------------------------------------

test "signcrypt seal and open with symmetric key only (C9)" {
    const allocator = std.testing.allocator;

    const msg = "symmetric key round-trip";
    const sym_key: types.SymmetricKey = [_]u8{0xCC} ** 32;
    const identifier = [_]u8{0xDD} ** 32;

    const sym_rcvs = [_]ReceiverSymmetricKey{
        .{ .symmetric_key = sym_key, .identifier = &identifier },
    };

    const sealed = try seal(allocator, msg, null, .{
        .receiver_symmetric_keys = &sym_rcvs,
    });
    defer allocator.free(sealed);

    // Open with symmetric key (no box keys).
    const empty_keyring = [_]key.BoxKeyPair{};
    const result = try open(allocator, sealed, &empty_keyring, null, .{
        .receiver_symmetric_keys = &sym_rcvs,
    });
    defer result.deinit();

    try std.testing.expectEqualStrings(msg, result.plaintext);
    try std.testing.expect(result.key_info.sender_is_anonymous);
}

test "signcrypt seal and open with symmetric key and signing key (C9)" {
    const allocator = std.testing.allocator;
    const signing_kp = key.SigningKeyPair.generate();

    const msg = "symmetric signed message";
    const sym_key: types.SymmetricKey = [_]u8{0xEE} ** 32;
    const identifier = [_]u8{0xFF} ** 32;

    const sym_rcvs = [_]ReceiverSymmetricKey{
        .{ .symmetric_key = sym_key, .identifier = &identifier },
    };

    const sealed = try seal(allocator, msg, signing_kp.secret_key, .{
        .receiver_symmetric_keys = &sym_rcvs,
    });
    defer allocator.free(sealed);

    // Open with symmetric key.
    const empty_keyring = [_]key.BoxKeyPair{};
    const lookup = struct {
        fn lookupFn(pk_bytes: [32]u8) ?key.SigningPublicKey {
            return key.SigningPublicKey.fromBytes(pk_bytes) catch return null;
        }
    };
    const result = try open(allocator, sealed, &empty_keyring, &lookup.lookupFn, .{
        .receiver_symmetric_keys = &sym_rcvs,
    });
    defer result.deinit();

    try std.testing.expectEqualStrings(msg, result.plaintext);
    try std.testing.expect(!result.key_info.sender_is_anonymous);
    try std.testing.expect(result.key_info.sender_key != null);
}

test "signcrypt open with wrong symmetric key fails (C9)" {
    const allocator = std.testing.allocator;

    const msg = "wrong sym key test";
    const sym_key: types.SymmetricKey = [_]u8{0x11} ** 32;
    const identifier = [_]u8{0x22} ** 32;

    const sym_rcvs = [_]ReceiverSymmetricKey{
        .{ .symmetric_key = sym_key, .identifier = &identifier },
    };

    const sealed = try seal(allocator, msg, null, .{
        .receiver_symmetric_keys = &sym_rcvs,
    });
    defer allocator.free(sealed);

    // Try to open with a different symmetric key (same identifier, different key).
    const wrong_key: types.SymmetricKey = [_]u8{0x99} ** 32;
    const wrong_sym_rcvs = [_]ReceiverSymmetricKey{
        .{ .symmetric_key = wrong_key, .identifier = &identifier },
    };

    const empty_keyring = [_]key.BoxKeyPair{};
    const result = open(allocator, sealed, &empty_keyring, null, .{
        .receiver_symmetric_keys = &wrong_sym_rcvs,
    });
    // The KID will match (same identifier) but decryption will fail because
    // the derived key is different (wrong symmetric key), so we expect
    // NoDecryptionKey (decryption of payload_key_box fails silently, no match found).
    try std.testing.expectError(sp_errors.Error.NoDecryptionKey, result);
}

test "signcrypt open with mixed box and symmetric recipients (C9)" {
    const allocator = std.testing.allocator;
    const signing_kp = key.SigningKeyPair.generate();
    const box_kp = key.BoxKeyPair.generate();

    const msg = "mixed recipients test";
    const sym_key: types.SymmetricKey = [_]u8{0x33} ** 32;
    const identifier = [_]u8{0x44} ** 32;

    const receiver_box_keys = [_]key.BoxPublicKey{box_kp.public_key};
    const sym_rcvs = [_]ReceiverSymmetricKey{
        .{ .symmetric_key = sym_key, .identifier = &identifier },
    };

    const sealed = try seal(allocator, msg, signing_kp.secret_key, .{
        .receiver_box_keys = &receiver_box_keys,
        .receiver_symmetric_keys = &sym_rcvs,
    });
    defer allocator.free(sealed);

    const lookup = struct {
        fn lookupFn(pk_bytes: [32]u8) ?key.SigningPublicKey {
            return key.SigningPublicKey.fromBytes(pk_bytes) catch return null;
        }
    };

    // Box recipient can open.
    {
        const keyring_keys = [_]key.BoxKeyPair{box_kp};
        const result = try open(allocator, sealed, &keyring_keys, &lookup.lookupFn, .{});
        defer result.deinit();
        try std.testing.expectEqualStrings(msg, result.plaintext);
    }

    // Symmetric key recipient can open.
    {
        const empty_keyring = [_]key.BoxKeyPair{};
        const result = try open(allocator, sealed, &empty_keyring, &lookup.lookupFn, .{
            .receiver_symmetric_keys = &sym_rcvs,
        });
        defer result.deinit();
        try std.testing.expectEqualStrings(msg, result.plaintext);
    }
}

// ---------------------------------------------------------------------------
// Tests for H2: No debug.assert on untrusted data
// ---------------------------------------------------------------------------

test "signcrypt secretBoxSeal rejects mismatched output buffer (H2)" {
    // Verify that secretBoxSeal returns an error (not a panic/assert)
    // when the output buffer has the wrong length.
    const key_val = [_]u8{0} ** 32;
    const nonce_val = [_]u8{0} ** 24;
    const msg = [_]u8{ 1, 2, 3, 4 };

    // Output buffer too small (should be msg.len + tag_length = 20, give 10).
    var bad_out: [10]u8 = undefined;
    const result = secretBoxSeal(&bad_out, &msg, nonce_val, key_val);
    try std.testing.expectError(sp_errors.Error.BadCiphertext, result);
}

test "signcrypt secretBoxOpen rejects mismatched output buffer (H2)" {
    // Verify that secretBoxOpen returns an error (not a panic/assert)
    // when the output buffer has the wrong length.
    const key_val = [_]u8{0} ** 32;
    const nonce_val = [_]u8{0} ** 24;

    // Create a fake ciphertext (tag + encrypted data = 20 bytes).
    const ct = [_]u8{0} ** 20;

    // Output buffer wrong size (should be 20 - 16 = 4, give 10).
    var bad_out: [10]u8 = undefined;
    const result = secretBoxOpen(&bad_out, &ct, nonce_val, key_val);
    try std.testing.expectError(sp_errors.Error.BadCiphertext, result);
}

// ---------------------------------------------------------------------------
// Tests for M12: Variable-length symmetric identifiers (Go parity)
// ---------------------------------------------------------------------------

test "signcrypt symmetric KID is raw identifier in header (M12)" {
    // Verify that the header stores the raw identifier bytes, not a hash.
    const allocator = std.testing.allocator;

    const sym_key: types.SymmetricKey = [_]u8{0xAB} ** 32;
    const short_id = [_]u8{0xCD} ** 16;

    const sym_rcvs = [_]ReceiverSymmetricKey{
        .{ .symmetric_key = sym_key, .identifier = &short_id },
    };

    const sealed = try seal(allocator, "test", null, .{
        .receiver_symmetric_keys = &sym_rcvs,
    });
    defer allocator.free(sealed);

    // Decode header and check that the KID matches the raw 16-byte identifier.
    const hdr_result = try decodeHeaderFromStream(allocator, sealed);
    const hdr = hdr_result.header;
    defer {
        allocator.free(hdr.sender_secretbox);
        header_mod.freeDecodedReceivers(allocator, hdr.receivers);
    }

    try std.testing.expectEqual(@as(usize, 1), hdr.receivers.len);
    const kid = hdr.receivers[0].recipient_kid.?;
    try std.testing.expectEqual(@as(usize, 16), kid.len);
    try std.testing.expectEqualSlices(u8, &short_id, kid);
}

test "signcrypt seal and open with non-32-byte symmetric identifier (M12)" {
    const allocator = std.testing.allocator;

    const msg = "variable-length identifier test";
    const sym_key: types.SymmetricKey = [_]u8{0x55} ** 32;
    // Use a 16-byte identifier (shorter than 32).
    const short_id = [_]u8{0x66} ** 16;

    const sym_rcvs = [_]ReceiverSymmetricKey{
        .{ .symmetric_key = sym_key, .identifier = &short_id },
    };

    const sealed = try seal(allocator, msg, null, .{
        .receiver_symmetric_keys = &sym_rcvs,
    });
    defer allocator.free(sealed);

    // Open with the same short identifier.
    const empty_keyring = [_]key.BoxKeyPair{};
    const result = try open(allocator, sealed, &empty_keyring, null, .{
        .receiver_symmetric_keys = &sym_rcvs,
    });
    defer result.deinit();

    try std.testing.expectEqualStrings(msg, result.plaintext);
}

test "signcrypt and open 1-byte message" {
    const allocator = std.testing.allocator;
    const signing_kp = key.SigningKeyPair.generate();
    const box_kp = key.BoxKeyPair.generate();

    const msg = "X";
    const receiver_box_keys = [_]key.BoxPublicKey{box_kp.public_key};

    const sealed = try seal(allocator, msg, signing_kp.secret_key, .{
        .receiver_box_keys = &receiver_box_keys,
    });
    defer allocator.free(sealed);

    const keyring_keys = [_]key.BoxKeyPair{box_kp};
    const lookup = struct {
        fn lookupFn(pk_bytes: [32]u8) ?key.SigningPublicKey {
            return key.SigningPublicKey.fromBytes(pk_bytes) catch return null;
        }
    };

    const result = try open(allocator, sealed, &keyring_keys, &lookup.lookupFn, .{});
    defer result.deinit();

    try std.testing.expectEqualStrings(msg, result.plaintext);
    try std.testing.expect(!result.key_info.sender_is_anonymous);
}

test "signcrypt seal and open with long symmetric identifier (M12)" {
    const allocator = std.testing.allocator;

    const msg = "long identifier test";
    const sym_key: types.SymmetricKey = [_]u8{0x77} ** 32;
    // Use a 64-byte identifier (longer than 32).
    const long_id = [_]u8{0x88} ** 64;

    const sym_rcvs = [_]ReceiverSymmetricKey{
        .{ .symmetric_key = sym_key, .identifier = &long_id },
    };

    const sealed = try seal(allocator, msg, null, .{
        .receiver_symmetric_keys = &sym_rcvs,
    });
    defer allocator.free(sealed);

    // Open with the same long identifier.
    const empty_keyring = [_]key.BoxKeyPair{};
    const result = try open(allocator, sealed, &empty_keyring, null, .{
        .receiver_symmetric_keys = &sym_rcvs,
    });
    defer result.deinit();

    try std.testing.expectEqualStrings(msg, result.plaintext);
}

// ---------------------------------------------------------------------------
// Tests for anonymous sender signature zero-check
// ---------------------------------------------------------------------------

test "signcrypt open rejects non-zero signature in anonymous sender mode" {
    // Verify that the anonymous sender mode still works correctly (zero sig bytes pass).
    const allocator = std.testing.allocator;
    const box_kp = key.BoxKeyPair.generate();

    const msg = "anonymous sig check test";
    const receiver_box_keys = [_]key.BoxPublicKey{box_kp.public_key};

    // Seal with anonymous sender (null signing key) - should produce zero sig bytes.
    const sealed = try seal(allocator, msg, null, .{
        .receiver_box_keys = &receiver_box_keys,
    });
    defer allocator.free(sealed);

    // The sealed message should open correctly (zero sig bytes pass the check).
    const keyring_keys = [_]key.BoxKeyPair{box_kp};
    const open_result = try open(allocator, sealed, &keyring_keys, null, .{});
    defer open_result.deinit();
    try std.testing.expectEqualStrings(msg, open_result.plaintext);
    try std.testing.expect(open_result.key_info.sender_is_anonymous);
}

// ---------------------------------------------------------------------------
// Tests for duplicate receiver detection
// ---------------------------------------------------------------------------

test "signcrypt seal rejects duplicate box receivers" {
    const allocator = std.testing.allocator;
    const signing_kp = key.SigningKeyPair.generate();
    const box_kp = key.BoxKeyPair.generate();

    // Pass the same box key twice.
    const receiver_box_keys = [_]key.BoxPublicKey{ box_kp.public_key, box_kp.public_key };
    const seal_result = seal(allocator, "test", signing_kp.secret_key, .{
        .receiver_box_keys = &receiver_box_keys,
    });
    try std.testing.expectError(sp_errors.Error.RepeatedKey, seal_result);
}

test "signcrypt seal allows distinct box receivers" {
    const allocator = std.testing.allocator;
    const signing_kp = key.SigningKeyPair.generate();
    const box_kp1 = key.BoxKeyPair.generate();
    const box_kp2 = key.BoxKeyPair.generate();

    // Two different box keys should succeed.
    const receiver_box_keys = [_]key.BoxPublicKey{ box_kp1.public_key, box_kp2.public_key };
    const sealed = try seal(allocator, "test", signing_kp.secret_key, .{
        .receiver_box_keys = &receiver_box_keys,
    });
    defer allocator.free(sealed);
    try std.testing.expect(sealed.len > 0);
}
