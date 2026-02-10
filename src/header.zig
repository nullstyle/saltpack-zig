//! Header encoding and decoding with double-encoding and SHA-512 hash computation.
//!
//! Implements the saltpack header format for both encryption and signature messages.
//! The header undergoes "double encoding": first the header fields are serialized
//! as a msgpack array, then that byte string is serialized as a msgpack bin.
//! A SHA-512 hash of the inner encoding (the array bytes) is computed and returned
//! alongside the double-encoded output.

const std = @import("std");
const types = @import("types.zig");
const sp_errors = @import("errors.zig");
const Allocator = std.mem.Allocator;
const Sha512 = std.crypto.hash.sha2.Sha512;

// ---------------------------------------------------------------------------
// Public types
// ---------------------------------------------------------------------------

/// Keys for a single recipient in an encryption header.
pub const ReceiverKeys = struct {
    /// The recipient's key identifier (variable length), or null for hidden recipients.
    /// In the encryption mode this is always 32 bytes (the raw public key bytes).
    /// In the signcryption mode this may be any length (Go uses `[]byte`).
    recipient_kid: ?[]const u8,
    /// The encrypted payload key for this recipient.
    payload_key_box: []const u8,
};

/// Free all heap-allocated data within a decoded receivers slice and the slice itself.
/// This covers both `recipient_kid` (variable-length, heap-allocated by the decoder)
/// and `payload_key_box`. Call this instead of manually iterating receiver fields.
pub fn freeDecodedReceivers(allocator: Allocator, receivers: []const ReceiverKeys) void {
    for (receivers) |rcv| {
        if (rcv.recipient_kid) |kid| {
            if (kid.len > 0) allocator.free(kid);
        }
        if (rcv.payload_key_box.len > 0) allocator.free(rcv.payload_key_box);
    }
    allocator.free(receivers);
}

/// The parsed encryption header fields (encryption or signcryption).
pub const EncryptionHeader = struct {
    version: types.Version,
    message_type: types.MessageType,
    ephemeral_key: [32]u8,
    sender_secretbox: []const u8,
    receivers: []const ReceiverKeys,
};

/// The parsed signature header fields (attached or detached).
pub const SignatureHeader = struct {
    version: types.Version,
    message_type: types.MessageType,
    sender_public_key: [32]u8,
    nonce: [16]u8,
};

/// The result of encoding a header: the double-encoded bytes and the header hash.
pub const HeaderResult = struct {
    header_hash: types.HeaderHash,
    encoded: []const u8,
};

/// A decoded header — either encryption or signature — together with its hash.
pub const DecodedHeader = union(enum) {
    encryption: struct {
        header: EncryptionHeader,
        hash: types.HeaderHash,
    },
    signature: struct {
        header: SignatureHeader,
        hash: types.HeaderHash,
    },
};

/// Maximum allowed length for sender_secretbox and payload_key_box fields.
/// Legitimate values are 48 bytes; 256 is a generous upper bound to reject
/// absurdly large allocations from crafted headers.
const max_box_field_length: usize = 256;

// ---------------------------------------------------------------------------
// Msgpack packer type alias
// ---------------------------------------------------------------------------

const mp_utils = @import("msgpack_utils.zig");
const MsgPack = mp_utils.MsgPack;
const BufferStream = mp_utils.BufferStream;
const fixedBufferStream = mp_utils.fixedBufferStream;
const Payload = mp_utils.Payload;

// ---------------------------------------------------------------------------
// Encoding
// ---------------------------------------------------------------------------

/// Encode an encryption header with double-encoding.
/// Returns the header hash (SHA-512 of the inner msgpack array encoding)
/// and the double-encoded bytes (the inner bytes wrapped in a msgpack bin).
///
/// Returns `error.TooManyReceivers` if the number of receivers exceeds
/// `types.max_receiver_count` (2048).
pub fn encodeEncryptionHeader(allocator: Allocator, header: EncryptionHeader) !HeaderResult {
    if (header.receivers.len > types.max_receiver_count) return sp_errors.Error.TooManyReceivers;

    // Build the inner msgpack array: 6 elements
    // [format_name, [major, minor], type, ephemeral_key, sender_secretbox, receivers]
    var arr = try Payload.arrPayload(6, allocator);

    // 0: format name
    const name_payload = try Payload.strToPayload(types.format_name, allocator);
    try arr.setArrElement(0, name_payload);

    // 1: version [major, minor]
    var ver_arr = try Payload.arrPayload(2, allocator);
    try ver_arr.setArrElement(0, Payload.uintToPayload(header.version.major));
    try ver_arr.setArrElement(1, Payload.uintToPayload(header.version.minor));
    try arr.setArrElement(1, ver_arr);

    // 2: message type
    try arr.setArrElement(2, Payload.uintToPayload(@intFromEnum(header.message_type)));

    // 3: ephemeral key (bin 32)
    const eph_payload = try Payload.binToPayload(&header.ephemeral_key, allocator);
    try arr.setArrElement(3, eph_payload);

    // 4: sender secretbox (bin)
    const sb_payload = try Payload.binToPayload(header.sender_secretbox, allocator);
    try arr.setArrElement(4, sb_payload);

    // 5: receivers list
    var rcv_arr = try Payload.arrPayload(header.receivers.len, allocator);
    for (header.receivers, 0..) |rcv, i| {
        var pair = try Payload.arrPayload(2, allocator);

        // receiver KID: bin or nil
        if (rcv.recipient_kid) |kid| {
            const kid_payload = try Payload.binToPayload(kid, allocator);
            try pair.setArrElement(0, kid_payload);
        } else {
            try pair.setArrElement(0, Payload.nilToPayload());
        }

        // payload key box: bin
        const pkb_payload = try Payload.binToPayload(rcv.payload_key_box, allocator);
        try pair.setArrElement(1, pkb_payload);

        try rcv_arr.setArrElement(i, pair);
    }
    try arr.setArrElement(5, rcv_arr);

    return doubleEncode(allocator, arr);
}

/// Encode a signature header with double-encoding.
/// Returns the header hash and the double-encoded bytes.
pub fn encodeSignatureHeader(allocator: Allocator, header: SignatureHeader) !HeaderResult {
    // Build the inner msgpack array: 5 elements
    // [format_name, [major, minor], type, sender_public_key, nonce]
    var arr = try Payload.arrPayload(5, allocator);

    // 0: format name
    const name_payload = try Payload.strToPayload(types.format_name, allocator);
    try arr.setArrElement(0, name_payload);

    // 1: version [major, minor]
    var ver_arr = try Payload.arrPayload(2, allocator);
    try ver_arr.setArrElement(0, Payload.uintToPayload(header.version.major));
    try ver_arr.setArrElement(1, Payload.uintToPayload(header.version.minor));
    try arr.setArrElement(1, ver_arr);

    // 2: message type
    try arr.setArrElement(2, Payload.uintToPayload(@intFromEnum(header.message_type)));

    // 3: sender public key (bin 32)
    const spk_payload = try Payload.binToPayload(&header.sender_public_key, allocator);
    try arr.setArrElement(3, spk_payload);

    // 4: nonce (bin 16)
    const nonce_payload = try Payload.binToPayload(&header.nonce, allocator);
    try arr.setArrElement(4, nonce_payload);

    return doubleEncode(allocator, arr);
}

/// Decode a double-encoded header from raw bytes.
/// Returns a DecodedHeader (encryption or signature) and the header hash.
pub fn decodeHeader(allocator: Allocator, data: []const u8) !DecodedHeader {
    // Step 1: Read outer msgpack bin from the data.
    // Dynamically allocate the read buffer to support headers with many receivers.
    const read_buf_storage = try allocator.alloc(u8, data.len);
    defer allocator.free(read_buf_storage);
    @memcpy(read_buf_storage, data);
    var read_buf = fixedBufferStream(read_buf_storage);

    // We need a dummy write buffer for the packer (we only read here).
    var dummy_write_buf_storage: [1]u8 = undefined;
    var dummy_write_buf = fixedBufferStream(&dummy_write_buf_storage);

    var packer = MsgPack.init(&dummy_write_buf, &read_buf);

    const outer_payload = try packer.read(allocator);
    defer outer_payload.free(allocator);

    // The outer layer must be a bin (the inner header bytes).
    const header_bytes: []const u8 = switch (outer_payload) {
        .bin => |b| b.bin,
        else => return sp_errors.Error.FailedToReadHeaderBytes,
    };

    // Step 2: Compute header hash = SHA-512(headerBytes).
    var header_hash: types.HeaderHash = undefined;
    Sha512.hash(header_bytes, &header_hash, .{});

    // Step 3: Decode the inner msgpack array from headerBytes.
    // Dynamically allocate the inner read buffer to support large headers.
    const inner_read_storage = try allocator.alloc(u8, header_bytes.len);
    defer allocator.free(inner_read_storage);
    @memcpy(inner_read_storage, header_bytes);
    var inner_read_buf = fixedBufferStream(inner_read_storage);
    var inner_dummy_write_storage: [1]u8 = undefined;
    var inner_dummy_write = fixedBufferStream(&inner_dummy_write_storage);

    var inner_packer = MsgPack.init(&inner_dummy_write, &inner_read_buf);
    const inner_payload = try inner_packer.read(allocator);
    defer inner_payload.free(allocator);

    // Must be an array.
    const arr_items = switch (inner_payload) {
        .arr => |a| a,
        else => return sp_errors.Error.FailedToReadHeaderBytes,
    };

    // Validate minimum array length before accessing elements.
    // The smallest valid header (signature) has 5 elements; encryption has 6.
    // We need at least 3 elements to read format_name, version, and message_type.
    if (arr_items.len < 3) return sp_errors.Error.NotASaltpackMessage;

    // Validate format name (element 0).
    const format_name_str = switch (arr_items[0]) {
        .str => |s| s.str,
        else => return sp_errors.Error.NotASaltpackMessage,
    };
    if (!std.mem.eql(u8, format_name_str, types.format_name)) {
        return sp_errors.Error.NotASaltpackMessage;
    }

    // Parse version (element 1): [major, minor]
    const ver_arr = switch (arr_items[1]) {
        .arr => |a| a,
        else => return sp_errors.Error.BadVersion,
    };
    if (ver_arr.len != 2) return sp_errors.Error.BadVersion;

    const major = try payloadToU32(ver_arr[0]);
    const minor = try payloadToU32(ver_arr[1]);
    const version = types.Version{ .major = major, .minor = minor };

    // Validate version is known.
    var version_known = false;
    for (types.Version.knownVersions()) |kv| {
        if (kv.major == version.major) {
            version_known = true;
            break;
        }
    }
    if (!version_known) return sp_errors.Error.BadVersion;

    // Parse message type (element 2).
    const msg_type_int = try payloadToU8(arr_items[2]);
    const message_type = std.meta.intToEnum(types.MessageType, msg_type_int) catch {
        return sp_errors.Error.WrongMessageType;
    };

    // Dispatch based on array length and message type.
    if (arr_items.len == 6) {
        // Encryption or signcryption header.
        if (message_type != .encryption and message_type != .signcryption) {
            return sp_errors.Error.WrongMessageType;
        }
        return DecodedHeader{
            .encryption = .{
                .header = try parseEncryptionFields(allocator, arr_items, version, message_type),
                .hash = header_hash,
            },
        };
    } else if (arr_items.len == 5) {
        // Signature header.
        if (message_type != .attached_signature and message_type != .detached_signature) {
            return sp_errors.Error.WrongMessageType;
        }
        return DecodedHeader{
            .signature = .{
                .header = try parseSignatureFields(arr_items, version, message_type),
                .hash = header_hash,
            },
        };
    } else {
        return sp_errors.Error.FailedToReadHeaderBytes;
    }
}

// ---------------------------------------------------------------------------
// Internal helpers
// ---------------------------------------------------------------------------

/// Perform the double-encoding: serialize the payload array to bytes (inner),
/// hash those bytes, then wrap them as a msgpack bin (outer).
fn doubleEncode(allocator: Allocator, arr: Payload) !HeaderResult {
    defer {
        var a = arr;
        a.free(allocator);
    }

    // Estimate the buffer size needed for serialization.
    // Base overhead for header fields (format_name, version, type, keys, etc.) plus
    // generous per-receiver estimate (KID + payload_key_box + msgpack framing).
    const encode_buf_size = estimateHeaderBufSize(arr);

    // Serialize the inner array to bytes using a dynamically allocated buffer.
    const inner_buf_storage = try allocator.alloc(u8, encode_buf_size);
    defer allocator.free(inner_buf_storage);
    var inner_write_buf = fixedBufferStream(inner_buf_storage);
    var inner_dummy_read_storage: [1]u8 = undefined;
    var inner_dummy_read = fixedBufferStream(&inner_dummy_read_storage);

    var inner_packer = MsgPack.init(&inner_write_buf, &inner_dummy_read);
    try inner_packer.write(arr);

    const inner_len = inner_write_buf.pos;
    const inner_bytes = inner_buf_storage[0..inner_len];

    // Compute the header hash = SHA-512(innerBytes).
    var header_hash: types.HeaderHash = undefined;
    Sha512.hash(inner_bytes, &header_hash, .{});

    // Now double-encode: wrap the inner bytes as a msgpack bin.
    const bin_payload = try Payload.binToPayload(inner_bytes, allocator);
    defer {
        var bp = bin_payload;
        bp.free(allocator);
    }

    // The outer encoding is the inner bytes wrapped as msgpack bin, so it needs
    // inner_len + a small overhead for the bin header (up to 5 bytes).
    const outer_buf_size = inner_len + 16;
    const outer_buf_storage = try allocator.alloc(u8, outer_buf_size);
    defer allocator.free(outer_buf_storage);
    var outer_write_buf = fixedBufferStream(outer_buf_storage);
    var outer_dummy_read_storage: [1]u8 = undefined;
    var outer_dummy_read = fixedBufferStream(&outer_dummy_read_storage);

    var outer_packer = MsgPack.init(&outer_write_buf, &outer_dummy_read);
    try outer_packer.write(bin_payload);

    const outer_len = outer_write_buf.pos;

    // Allocate the result and copy.
    const encoded = try allocator.alloc(u8, outer_len);
    @memcpy(encoded, outer_buf_storage[0..outer_len]);

    return HeaderResult{
        .header_hash = header_hash,
        .encoded = encoded,
    };
}

/// Estimate the buffer size needed to serialize a header Payload.
///
/// For encryption headers (6-element arrays), the buffer must accommodate
/// all receiver entries. For signature headers (5-element arrays), a small
/// fixed size suffices. Returns a generous estimate to avoid buffer overflows.
fn estimateHeaderBufSize(arr: Payload) usize {
    const base_size: usize = 1024; // generous base for non-receiver fields
    const per_receiver: usize = 256; // generous per-receiver estimate
    switch (arr) {
        .arr => |items| {
            if (items.len == 6) {
                // Encryption header: element 5 is the receiver array.
                const receiver_count = switch (items[5]) {
                    .arr => |rcv| rcv.len,
                    else => 0,
                };
                return base_size + receiver_count * per_receiver;
            }
        },
        else => {},
    }
    return base_size;
}

fn parseEncryptionFields(allocator: Allocator, arr_items: []Payload, version: types.Version, message_type: types.MessageType) !EncryptionHeader {
    // Element 3: ephemeral key (bin 32)
    const eph_bytes = switch (arr_items[3]) {
        .bin => |b| b.bin,
        else => return sp_errors.Error.BadEphemeralKey,
    };
    if (eph_bytes.len != 32) return sp_errors.Error.BadEphemeralKey;

    var ephemeral_key: [32]u8 = undefined;
    @memcpy(&ephemeral_key, eph_bytes);

    // Element 4: sender secretbox (bin)
    const sb_bytes = switch (arr_items[4]) {
        .bin => |b| b.bin,
        else => return sp_errors.Error.BadSenderKeySecretbox,
    };
    if (sb_bytes.len > max_box_field_length) return sp_errors.Error.BadSenderKeySecretbox;
    const sender_secretbox = try allocator.alloc(u8, sb_bytes.len);
    @memcpy(sender_secretbox, sb_bytes);
    errdefer allocator.free(sender_secretbox);

    // Element 5: receivers list (array of pairs)
    const rcv_items = switch (arr_items[5]) {
        .arr => |a| a,
        else => return sp_errors.Error.BadReceivers,
    };

    // Enforce the maximum receiver count to prevent excessive memory usage.
    if (rcv_items.len > types.max_receiver_count) return sp_errors.Error.TooManyReceivers;

    const receivers = try allocator.alloc(ReceiverKeys, rcv_items.len);
    errdefer {
        for (receivers) |r| {
            if (r.recipient_kid) |kid| {
                if (kid.len > 0) allocator.free(kid);
            }
            if (r.payload_key_box.len > 0) allocator.free(r.payload_key_box);
        }
        allocator.free(receivers);
    }

    // Initialize all entries to safe defaults so the errdefer can safely iterate.
    for (receivers) |*r| {
        r.* = ReceiverKeys{ .recipient_kid = null, .payload_key_box = &.{} };
    }

    for (rcv_items, 0..) |rcv_payload, i| {
        const pair = switch (rcv_payload) {
            .arr => |a| a,
            else => return sp_errors.Error.BadReceivers,
        };
        if (pair.len != 2) return sp_errors.Error.BadReceivers;

        // recipient KID: bin or nil (variable length to match Go's []byte)
        var recipient_kid: ?[]const u8 = null;
        switch (pair[0]) {
            .nil => {},
            .bin => |b| {
                const kid = try allocator.alloc(u8, b.bin.len);
                @memcpy(kid, b.bin);
                recipient_kid = kid;
            },
            else => return sp_errors.Error.BadReceivers,
        }

        // payload key box: bin
        const pkb_bytes = switch (pair[1]) {
            .bin => |b| b.bin,
            else => return sp_errors.Error.BadReceivers,
        };
        if (pkb_bytes.len > max_box_field_length) return sp_errors.Error.BadReceivers;
        const payload_key_box = try allocator.alloc(u8, pkb_bytes.len);
        @memcpy(payload_key_box, pkb_bytes);

        receivers[i] = ReceiverKeys{
            .recipient_kid = recipient_kid,
            .payload_key_box = payload_key_box,
        };
    }

    return EncryptionHeader{
        .version = version,
        .message_type = message_type,
        .ephemeral_key = ephemeral_key,
        .sender_secretbox = sender_secretbox,
        .receivers = receivers,
    };
}

fn parseSignatureFields(arr_items: []Payload, version: types.Version, message_type: types.MessageType) !SignatureHeader {
    // Element 3: sender public key (bin 32)
    const spk_bytes = switch (arr_items[3]) {
        .bin => |b| b.bin,
        else => return sp_errors.Error.BadSignature,
    };
    if (spk_bytes.len != 32) return sp_errors.Error.BadSignature;

    var sender_public_key: [32]u8 = undefined;
    @memcpy(&sender_public_key, spk_bytes);

    // Element 4: nonce (bin 16)
    const nonce_bytes = switch (arr_items[4]) {
        .bin => |b| b.bin,
        else => return sp_errors.Error.BadSignature,
    };
    if (nonce_bytes.len != 16) return sp_errors.Error.BadSignature;

    var nonce_val: [16]u8 = undefined;
    @memcpy(&nonce_val, nonce_bytes);

    return SignatureHeader{
        .version = version,
        .message_type = message_type,
        .sender_public_key = sender_public_key,
        .nonce = nonce_val,
    };
}

fn payloadToU32(p: Payload) !u32 {
    return switch (p) {
        .uint => |v| std.math.cast(u32, v) orelse return sp_errors.Error.BadVersion,
        .int => |v| std.math.cast(u32, v) orelse return sp_errors.Error.BadVersion,
        else => sp_errors.Error.BadVersion,
    };
}

fn payloadToU8(p: Payload) !u8 {
    return switch (p) {
        .uint => |v| std.math.cast(u8, v) orelse return sp_errors.Error.WrongMessageType,
        .int => |v| std.math.cast(u8, v) orelse return sp_errors.Error.WrongMessageType,
        else => sp_errors.Error.WrongMessageType,
    };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "encode encryption header round-trip" {
    const allocator = std.testing.allocator;

    const ephemeral_key = [_]u8{0x01} ** 32;
    const sender_secretbox = [_]u8{0x02} ** 48;
    const kid1 = [_]u8{0x03} ** 32;
    const pkb1 = [_]u8{0x04} ** 64;

    const receivers = [_]ReceiverKeys{
        .{
            .recipient_kid = &kid1,
            .payload_key_box = &pkb1,
        },
    };

    const header = EncryptionHeader{
        .version = types.Version.v2(),
        .message_type = .encryption,
        .ephemeral_key = ephemeral_key,
        .sender_secretbox = &sender_secretbox,
        .receivers = &receivers,
    };

    const result = try encodeEncryptionHeader(allocator, header);
    defer allocator.free(result.encoded);

    // Decode it back.
    const decoded = try decodeHeader(allocator, result.encoded);

    switch (decoded) {
        .encryption => |enc| {
            try std.testing.expect(enc.header.version.eql(types.Version.v2()));
            try std.testing.expectEqual(types.MessageType.encryption, enc.header.message_type);
            try std.testing.expectEqualSlices(u8, &ephemeral_key, &enc.header.ephemeral_key);
            try std.testing.expectEqualSlices(u8, &sender_secretbox, enc.header.sender_secretbox);
            try std.testing.expectEqual(@as(usize, 1), enc.header.receivers.len);
            try std.testing.expectEqualSlices(u8, &kid1, enc.header.receivers[0].recipient_kid.?);
            try std.testing.expectEqualSlices(u8, &pkb1, enc.header.receivers[0].payload_key_box);
            // Hash must match.
            try std.testing.expectEqualSlices(u8, &result.header_hash, &enc.hash);

            // Free decoded allocations.
            allocator.free(enc.header.sender_secretbox);
            freeDecodedReceivers(allocator, enc.header.receivers);
        },
        .signature => return error.TestUnexpectedResult,
    }
}

test "encode signature header round-trip" {
    const allocator = std.testing.allocator;

    const sender_pk = [_]u8{0xAA} ** 32;
    const nonce_val = [_]u8{0xBB} ** 16;

    const header = SignatureHeader{
        .version = types.Version.v2(),
        .message_type = .attached_signature,
        .sender_public_key = sender_pk,
        .nonce = nonce_val,
    };

    const result = try encodeSignatureHeader(allocator, header);
    defer allocator.free(result.encoded);

    const decoded = try decodeHeader(allocator, result.encoded);

    switch (decoded) {
        .signature => |sig| {
            try std.testing.expect(sig.header.version.eql(types.Version.v2()));
            try std.testing.expectEqual(types.MessageType.attached_signature, sig.header.message_type);
            try std.testing.expectEqualSlices(u8, &sender_pk, &sig.header.sender_public_key);
            try std.testing.expectEqualSlices(u8, &nonce_val, &sig.header.nonce);
            try std.testing.expectEqualSlices(u8, &result.header_hash, &sig.hash);
        },
        .encryption => return error.TestUnexpectedResult,
    }
}

test "header hash is SHA-512 of inner encoding" {
    const allocator = std.testing.allocator;

    const sender_pk = [_]u8{0x55} ** 32;
    const nonce_val = [_]u8{0x66} ** 16;

    const header = SignatureHeader{
        .version = types.Version.v1(),
        .message_type = .detached_signature,
        .sender_public_key = sender_pk,
        .nonce = nonce_val,
    };

    const result = try encodeSignatureHeader(allocator, header);
    defer allocator.free(result.encoded);

    // The outer encoding is a msgpack bin wrapping the inner bytes.
    // Decode the outer bin to get the inner bytes, then SHA-512 them manually.
    var read_storage: [65536]u8 = undefined;
    @memcpy(read_storage[0..result.encoded.len], result.encoded);
    var read_buf = fixedBufferStream(read_storage[0..result.encoded.len]);
    var dummy_write_storage: [1]u8 = undefined;
    var dummy_write = fixedBufferStream(&dummy_write_storage);
    var packer = MsgPack.init(&dummy_write, &read_buf);

    const outer = try packer.read(allocator);
    defer outer.free(allocator);

    const inner_bytes = switch (outer) {
        .bin => |b| b.bin,
        else => return error.TestUnexpectedResult,
    };

    var expected_hash: types.HeaderHash = undefined;
    Sha512.hash(inner_bytes, &expected_hash, .{});

    try std.testing.expectEqualSlices(u8, &expected_hash, &result.header_hash);
}

test "double encoding structure" {
    const allocator = std.testing.allocator;

    const sender_pk = [_]u8{0x77} ** 32;
    const nonce_val = [_]u8{0x88} ** 16;

    const header = SignatureHeader{
        .version = types.Version.v2(),
        .message_type = .attached_signature,
        .sender_public_key = sender_pk,
        .nonce = nonce_val,
    };

    const result = try encodeSignatureHeader(allocator, header);
    defer allocator.free(result.encoded);

    // The outer layer should decode as a msgpack bin.
    var read_storage: [65536]u8 = undefined;
    @memcpy(read_storage[0..result.encoded.len], result.encoded);
    var read_buf = fixedBufferStream(read_storage[0..result.encoded.len]);
    var dummy_write_storage: [1]u8 = undefined;
    var dummy_write = fixedBufferStream(&dummy_write_storage);
    var outer_packer = MsgPack.init(&dummy_write, &read_buf);

    const outer = try outer_packer.read(allocator);
    defer outer.free(allocator);

    // Outer must be bin.
    const inner_bytes = switch (outer) {
        .bin => |b| b.bin,
        else => return error.TestUnexpectedResult,
    };

    // Inner bytes should decode as a msgpack array.
    var inner_read_storage: [65536]u8 = undefined;
    @memcpy(inner_read_storage[0..inner_bytes.len], inner_bytes);
    var inner_read_buf = fixedBufferStream(inner_read_storage[0..inner_bytes.len]);
    var inner_dummy_write_storage: [1]u8 = undefined;
    var inner_dummy_write = fixedBufferStream(&inner_dummy_write_storage);
    var inner_packer = MsgPack.init(&inner_dummy_write, &inner_read_buf);

    const inner = try inner_packer.read(allocator);
    defer inner.free(allocator);

    // Must be an array with 5 elements (signature header).
    switch (inner) {
        .arr => |a| {
            try std.testing.expectEqual(@as(usize, 5), a.len);

            // Element 0 should be the format name string.
            const name = switch (a[0]) {
                .str => |s| s.str,
                else => return error.TestUnexpectedResult,
            };
            try std.testing.expectEqualStrings("saltpack", name);
        },
        else => return error.TestUnexpectedResult,
    }
}

test "encryption header with hidden recipients" {
    const allocator = std.testing.allocator;

    const ephemeral_key = [_]u8{0x10} ** 32;
    const sender_secretbox = [_]u8{0x20} ** 48;
    const pkb1 = [_]u8{0x30} ** 64;

    const receivers = [_]ReceiverKeys{
        .{
            .recipient_kid = null, // hidden recipient
            .payload_key_box = &pkb1,
        },
    };

    const header = EncryptionHeader{
        .version = types.Version.v2(),
        .message_type = .encryption,
        .ephemeral_key = ephemeral_key,
        .sender_secretbox = &sender_secretbox,
        .receivers = &receivers,
    };

    const result = try encodeEncryptionHeader(allocator, header);
    defer allocator.free(result.encoded);

    const decoded = try decodeHeader(allocator, result.encoded);

    switch (decoded) {
        .encryption => |enc| {
            try std.testing.expectEqual(@as(usize, 1), enc.header.receivers.len);
            // Hidden recipient: KID should be null.
            try std.testing.expect(enc.header.receivers[0].recipient_kid == null);
            try std.testing.expectEqualSlices(u8, &pkb1, enc.header.receivers[0].payload_key_box);

            // Free decoded allocations.
            allocator.free(enc.header.sender_secretbox);
            freeDecodedReceivers(allocator, enc.header.receivers);
        },
        .signature => return error.TestUnexpectedResult,
    }
}

test "encryption header with multiple recipients" {
    const allocator = std.testing.allocator;

    const ephemeral_key = [_]u8{0xA0} ** 32;
    const sender_secretbox = [_]u8{0xB0} ** 48;
    const kid1 = [_]u8{0xC1} ** 32;
    const kid2 = [_]u8{0xC2} ** 32;
    const kid3 = [_]u8{0xC3} ** 32;
    const pkb1 = [_]u8{0xD1} ** 64;
    const pkb2 = [_]u8{0xD2} ** 64;
    const pkb3 = [_]u8{0xD3} ** 64;

    const receivers = [_]ReceiverKeys{
        .{ .recipient_kid = &kid1, .payload_key_box = &pkb1 },
        .{ .recipient_kid = &kid2, .payload_key_box = &pkb2 },
        .{ .recipient_kid = &kid3, .payload_key_box = &pkb3 },
    };

    const header = EncryptionHeader{
        .version = types.Version.v2(),
        .message_type = .encryption,
        .ephemeral_key = ephemeral_key,
        .sender_secretbox = &sender_secretbox,
        .receivers = &receivers,
    };

    const result = try encodeEncryptionHeader(allocator, header);
    defer allocator.free(result.encoded);

    const decoded = try decodeHeader(allocator, result.encoded);

    switch (decoded) {
        .encryption => |enc| {
            try std.testing.expectEqual(@as(usize, 3), enc.header.receivers.len);

            try std.testing.expectEqualSlices(u8, &kid1, enc.header.receivers[0].recipient_kid.?);
            try std.testing.expectEqualSlices(u8, &kid2, enc.header.receivers[1].recipient_kid.?);
            try std.testing.expectEqualSlices(u8, &kid3, enc.header.receivers[2].recipient_kid.?);

            try std.testing.expectEqualSlices(u8, &pkb1, enc.header.receivers[0].payload_key_box);
            try std.testing.expectEqualSlices(u8, &pkb2, enc.header.receivers[1].payload_key_box);
            try std.testing.expectEqualSlices(u8, &pkb3, enc.header.receivers[2].payload_key_box);

            // Free decoded allocations.
            allocator.free(enc.header.sender_secretbox);
            freeDecodedReceivers(allocator, enc.header.receivers);
        },
        .signature => return error.TestUnexpectedResult,
    }
}

test "signature header attached vs detached" {
    const allocator = std.testing.allocator;

    const sender_pk = [_]u8{0xEE} ** 32;
    const nonce_val = [_]u8{0xFF} ** 16;

    // Test attached signature.
    {
        const header = SignatureHeader{
            .version = types.Version.v2(),
            .message_type = .attached_signature,
            .sender_public_key = sender_pk,
            .nonce = nonce_val,
        };

        const result = try encodeSignatureHeader(allocator, header);
        defer allocator.free(result.encoded);

        const decoded = try decodeHeader(allocator, result.encoded);
        switch (decoded) {
            .signature => |sig| {
                try std.testing.expectEqual(types.MessageType.attached_signature, sig.header.message_type);
            },
            .encryption => return error.TestUnexpectedResult,
        }
    }

    // Test detached signature.
    {
        const header = SignatureHeader{
            .version = types.Version.v2(),
            .message_type = .detached_signature,
            .sender_public_key = sender_pk,
            .nonce = nonce_val,
        };

        const result = try encodeSignatureHeader(allocator, header);
        defer allocator.free(result.encoded);

        const decoded = try decodeHeader(allocator, result.encoded);
        switch (decoded) {
            .signature => |sig| {
                try std.testing.expectEqual(types.MessageType.detached_signature, sig.header.message_type);
            },
            .encryption => return error.TestUnexpectedResult,
        }
    }
}

test "decode rejects wrong format name" {
    const allocator = std.testing.allocator;

    // Build a header array with wrong format name, then double-encode it manually.
    var arr = try Payload.arrPayload(5, allocator);

    const bad_name = try Payload.strToPayload("notpack", allocator);
    try arr.setArrElement(0, bad_name);

    var ver_arr = try Payload.arrPayload(2, allocator);
    try ver_arr.setArrElement(0, Payload.uintToPayload(2));
    try ver_arr.setArrElement(1, Payload.uintToPayload(0));
    try arr.setArrElement(1, ver_arr);

    try arr.setArrElement(2, Payload.uintToPayload(1)); // attached_signature
    const spk = try Payload.binToPayload(&([_]u8{0} ** 32), allocator);
    try arr.setArrElement(3, spk);
    const nonce_p = try Payload.binToPayload(&([_]u8{0} ** 16), allocator);
    try arr.setArrElement(4, nonce_p);

    // Serialize inner array.
    var inner_buf: [65536]u8 = undefined;
    var inner_write = fixedBufferStream(&inner_buf);
    var inner_dummy_read_storage: [1]u8 = undefined;
    var inner_dummy_read = fixedBufferStream(&inner_dummy_read_storage);
    var inner_packer = MsgPack.init(&inner_write, &inner_dummy_read);
    try inner_packer.write(arr);
    arr.free(allocator);

    const inner_len = inner_write.pos;

    // Wrap as bin.
    const bin_payload = try Payload.binToPayload(inner_buf[0..inner_len], allocator);
    defer bin_payload.free(allocator);

    var outer_buf: [65536]u8 = undefined;
    var outer_write = fixedBufferStream(&outer_buf);
    var outer_dummy_read_storage: [1]u8 = undefined;
    var outer_dummy_read = fixedBufferStream(&outer_dummy_read_storage);
    var outer_packer = MsgPack.init(&outer_write, &outer_dummy_read);
    try outer_packer.write(bin_payload);

    const outer_len = outer_write.pos;

    try std.testing.expectError(sp_errors.Error.NotASaltpackMessage, decodeHeader(allocator, outer_buf[0..outer_len]));
}

test "decode rejects unsupported version" {
    const allocator = std.testing.allocator;

    // Build a header array with unsupported version 99.0.
    var arr = try Payload.arrPayload(5, allocator);

    const name = try Payload.strToPayload("saltpack", allocator);
    try arr.setArrElement(0, name);

    var ver_arr = try Payload.arrPayload(2, allocator);
    try ver_arr.setArrElement(0, Payload.uintToPayload(99));
    try ver_arr.setArrElement(1, Payload.uintToPayload(0));
    try arr.setArrElement(1, ver_arr);

    try arr.setArrElement(2, Payload.uintToPayload(1)); // attached_signature
    const spk = try Payload.binToPayload(&([_]u8{0} ** 32), allocator);
    try arr.setArrElement(3, spk);
    const nonce_p = try Payload.binToPayload(&([_]u8{0} ** 16), allocator);
    try arr.setArrElement(4, nonce_p);

    // Serialize inner array.
    var inner_buf: [65536]u8 = undefined;
    var inner_write = fixedBufferStream(&inner_buf);
    var inner_dummy_read_storage: [1]u8 = undefined;
    var inner_dummy_read = fixedBufferStream(&inner_dummy_read_storage);
    var inner_packer = MsgPack.init(&inner_write, &inner_dummy_read);
    try inner_packer.write(arr);
    arr.free(allocator);

    const inner_len = inner_write.pos;

    // Wrap as bin.
    const bin_payload = try Payload.binToPayload(inner_buf[0..inner_len], allocator);
    defer bin_payload.free(allocator);

    var outer_buf: [65536]u8 = undefined;
    var outer_write = fixedBufferStream(&outer_buf);
    var outer_dummy_read_storage: [1]u8 = undefined;
    var outer_dummy_read = fixedBufferStream(&outer_dummy_read_storage);
    var outer_packer = MsgPack.init(&outer_write, &outer_dummy_read);
    try outer_packer.write(bin_payload);

    const outer_len = outer_write.pos;

    try std.testing.expectError(sp_errors.Error.BadVersion, decodeHeader(allocator, outer_buf[0..outer_len]));
}

test "encode rejects too many receivers" {
    const allocator = std.testing.allocator;

    const ephemeral_key = [_]u8{0x01} ** 32;
    const sender_secretbox = [_]u8{0x02} ** 48;
    const pkb = [_]u8{0x04} ** 64;

    // Create a receiver list that exceeds max_receiver_count.
    const too_many = types.max_receiver_count + 1;
    const receivers = try allocator.alloc(ReceiverKeys, too_many);
    defer allocator.free(receivers);
    for (receivers) |*r| {
        r.* = ReceiverKeys{ .recipient_kid = null, .payload_key_box = &pkb };
    }

    const header = EncryptionHeader{
        .version = types.Version.v2(),
        .message_type = .encryption,
        .ephemeral_key = ephemeral_key,
        .sender_secretbox = &sender_secretbox,
        .receivers = receivers,
    };

    try std.testing.expectError(sp_errors.Error.TooManyReceivers, encodeEncryptionHeader(allocator, header));
}

test "encode succeeds at exactly max receivers" {
    const allocator = std.testing.allocator;

    const ephemeral_key = [_]u8{0x01} ** 32;
    const sender_secretbox = [_]u8{0x02} ** 48;
    const pkb = [_]u8{0x04} ** 64;

    // Create a receiver list at exactly max_receiver_count.
    const receivers = try allocator.alloc(ReceiverKeys, types.max_receiver_count);
    defer allocator.free(receivers);
    for (receivers) |*r| {
        r.* = ReceiverKeys{ .recipient_kid = null, .payload_key_box = &pkb };
    }

    const header = EncryptionHeader{
        .version = types.Version.v2(),
        .message_type = .encryption,
        .ephemeral_key = ephemeral_key,
        .sender_secretbox = &sender_secretbox,
        .receivers = receivers,
    };

    // Encoding should succeed (not hit TooManyReceivers).
    const result = try encodeEncryptionHeader(allocator, header);
    defer allocator.free(result.encoded);

    // Decoding should also succeed and return the correct receiver count.
    const decoded = try decodeHeader(allocator, result.encoded);
    switch (decoded) {
        .encryption => |enc| {
            try std.testing.expectEqual(types.max_receiver_count, enc.header.receivers.len);

            // Free decoded allocations.
            allocator.free(enc.header.sender_secretbox);
            freeDecodedReceivers(allocator, enc.header.receivers);
        },
        .signature => return error.TestUnexpectedResult,
    }
}

test "decode rejects too many receivers" {
    const allocator = std.testing.allocator;

    // Build a header with too many receivers by constructing the msgpack manually.
    const too_many = types.max_receiver_count + 1;

    var arr = try Payload.arrPayload(6, allocator);

    const name_p = try Payload.strToPayload("saltpack", allocator);
    try arr.setArrElement(0, name_p);

    var ver_arr = try Payload.arrPayload(2, allocator);
    try ver_arr.setArrElement(0, Payload.uintToPayload(2));
    try ver_arr.setArrElement(1, Payload.uintToPayload(0));
    try arr.setArrElement(1, ver_arr);

    try arr.setArrElement(2, Payload.uintToPayload(0)); // encryption

    const eph_p = try Payload.binToPayload(&([_]u8{0} ** 32), allocator);
    try arr.setArrElement(3, eph_p);

    const sb_p = try Payload.binToPayload(&([_]u8{0} ** 48), allocator);
    try arr.setArrElement(4, sb_p);

    // Build a receiver array with too_many entries.
    var rcv_arr = try Payload.arrPayload(too_many, allocator);
    for (0..too_many) |i| {
        var pair = try Payload.arrPayload(2, allocator);
        try pair.setArrElement(0, Payload.nilToPayload());
        const pkb_p = try Payload.binToPayload(&([_]u8{0} ** 64), allocator);
        try pair.setArrElement(1, pkb_p);
        try rcv_arr.setArrElement(i, pair);
    }
    try arr.setArrElement(5, rcv_arr);

    // Serialize inner array using a dynamically allocated buffer.
    const inner_buf_size: usize = 1024 + too_many * 256;
    const inner_buf = try allocator.alloc(u8, inner_buf_size);
    defer allocator.free(inner_buf);
    var inner_write = fixedBufferStream(inner_buf);
    var inner_dummy_read_storage: [1]u8 = undefined;
    var inner_dummy_read = fixedBufferStream(&inner_dummy_read_storage);
    var inner_packer = MsgPack.init(&inner_write, &inner_dummy_read);
    try inner_packer.write(arr);
    arr.free(allocator);

    const inner_len = inner_write.pos;

    // Wrap as bin (double-encode).
    const bin_payload = try Payload.binToPayload(inner_buf[0..inner_len], allocator);
    defer bin_payload.free(allocator);

    const outer_buf_size = inner_len + 16;
    const outer_buf = try allocator.alloc(u8, outer_buf_size);
    defer allocator.free(outer_buf);
    var outer_write = fixedBufferStream(outer_buf);
    var outer_dummy_read_storage: [1]u8 = undefined;
    var outer_dummy_read = fixedBufferStream(&outer_dummy_read_storage);
    var outer_packer = MsgPack.init(&outer_write, &outer_dummy_read);
    try outer_packer.write(bin_payload);

    const outer_len = outer_write.pos;

    try std.testing.expectError(sp_errors.Error.TooManyReceivers, decodeHeader(allocator, outer_buf[0..outer_len]));
}

test "decode rejects header array with fewer than 3 elements" {
    const allocator = std.testing.allocator;

    // Build a header array with only 2 elements (format_name and version).
    // This should be rejected before accessing arr_items[2].
    var arr = try Payload.arrPayload(2, allocator);

    const name_p = try Payload.strToPayload("saltpack", allocator);
    try arr.setArrElement(0, name_p);

    var ver_arr = try Payload.arrPayload(2, allocator);
    try ver_arr.setArrElement(0, Payload.uintToPayload(2));
    try ver_arr.setArrElement(1, Payload.uintToPayload(0));
    try arr.setArrElement(1, ver_arr);

    // Serialize inner array.
    var inner_buf: [65536]u8 = undefined;
    var inner_write = fixedBufferStream(&inner_buf);
    var inner_dummy_read_storage: [1]u8 = undefined;
    var inner_dummy_read = fixedBufferStream(&inner_dummy_read_storage);
    var inner_packer = MsgPack.init(&inner_write, &inner_dummy_read);
    try inner_packer.write(arr);
    arr.free(allocator);

    const inner_len = inner_write.pos;

    // Wrap as bin (double-encode).
    const bin_payload = try Payload.binToPayload(inner_buf[0..inner_len], allocator);
    defer bin_payload.free(allocator);

    var outer_buf: [65536]u8 = undefined;
    var outer_write = fixedBufferStream(&outer_buf);
    var outer_dummy_read_storage: [1]u8 = undefined;
    var outer_dummy_read = fixedBufferStream(&outer_dummy_read_storage);
    var outer_packer = MsgPack.init(&outer_write, &outer_dummy_read);
    try outer_packer.write(bin_payload);

    const outer_len = outer_write.pos;

    try std.testing.expectError(sp_errors.Error.NotASaltpackMessage, decodeHeader(allocator, outer_buf[0..outer_len]));
}

test "decode rejects empty header array" {
    const allocator = std.testing.allocator;

    // Build a header array with 0 elements.
    var arr = try Payload.arrPayload(0, allocator);

    // Serialize inner array.
    var inner_buf: [65536]u8 = undefined;
    var inner_write = fixedBufferStream(&inner_buf);
    var inner_dummy_read_storage: [1]u8 = undefined;
    var inner_dummy_read = fixedBufferStream(&inner_dummy_read_storage);
    var inner_packer = MsgPack.init(&inner_write, &inner_dummy_read);
    try inner_packer.write(arr);
    arr.free(allocator);

    const inner_len = inner_write.pos;

    // Wrap as bin (double-encode).
    const bin_payload = try Payload.binToPayload(inner_buf[0..inner_len], allocator);
    defer bin_payload.free(allocator);

    var outer_buf: [65536]u8 = undefined;
    var outer_write = fixedBufferStream(&outer_buf);
    var outer_dummy_read_storage: [1]u8 = undefined;
    var outer_dummy_read = fixedBufferStream(&outer_dummy_read_storage);
    var outer_packer = MsgPack.init(&outer_write, &outer_dummy_read);
    try outer_packer.write(bin_payload);

    const outer_len = outer_write.pos;

    try std.testing.expectError(sp_errors.Error.NotASaltpackMessage, decodeHeader(allocator, outer_buf[0..outer_len]));
}

test "decode rejects oversized sender_secretbox" {
    const allocator = std.testing.allocator;

    // Build a valid-looking encryption header but with an oversized sender_secretbox (>256 bytes).
    var arr = try Payload.arrPayload(6, allocator);

    const name_p = try Payload.strToPayload("saltpack", allocator);
    try arr.setArrElement(0, name_p);

    var ver_arr = try Payload.arrPayload(2, allocator);
    try ver_arr.setArrElement(0, Payload.uintToPayload(2));
    try ver_arr.setArrElement(1, Payload.uintToPayload(0));
    try arr.setArrElement(1, ver_arr);

    try arr.setArrElement(2, Payload.uintToPayload(0)); // encryption

    const eph_p = try Payload.binToPayload(&([_]u8{0} ** 32), allocator);
    try arr.setArrElement(3, eph_p);

    // Oversized sender_secretbox: 257 bytes (exceeds max_box_field_length of 256).
    const oversized_sb = try allocator.alloc(u8, 257);
    defer allocator.free(oversized_sb);
    @memset(oversized_sb, 0xAA);
    const sb_p = try Payload.binToPayload(oversized_sb, allocator);
    try arr.setArrElement(4, sb_p);

    // Minimal receiver list.
    var rcv_arr = try Payload.arrPayload(1, allocator);
    var pair = try Payload.arrPayload(2, allocator);
    try pair.setArrElement(0, Payload.nilToPayload());
    const pkb_p = try Payload.binToPayload(&([_]u8{0} ** 48), allocator);
    try pair.setArrElement(1, pkb_p);
    try rcv_arr.setArrElement(0, pair);
    try arr.setArrElement(5, rcv_arr);

    // Serialize inner array.
    const inner_buf = try allocator.alloc(u8, 65536);
    defer allocator.free(inner_buf);
    var inner_write = fixedBufferStream(inner_buf);
    var inner_dummy_read_storage: [1]u8 = undefined;
    var inner_dummy_read = fixedBufferStream(&inner_dummy_read_storage);
    var inner_packer = MsgPack.init(&inner_write, &inner_dummy_read);
    try inner_packer.write(arr);
    arr.free(allocator);

    const inner_len = inner_write.pos;

    // Wrap as bin.
    const bin_payload = try Payload.binToPayload(inner_buf[0..inner_len], allocator);
    defer bin_payload.free(allocator);

    const outer_buf = try allocator.alloc(u8, inner_len + 16);
    defer allocator.free(outer_buf);
    var outer_write = fixedBufferStream(outer_buf);
    var outer_dummy_read_storage: [1]u8 = undefined;
    var outer_dummy_read = fixedBufferStream(&outer_dummy_read_storage);
    var outer_packer = MsgPack.init(&outer_write, &outer_dummy_read);
    try outer_packer.write(bin_payload);

    const outer_len = outer_write.pos;

    try std.testing.expectError(sp_errors.Error.BadSenderKeySecretbox, decodeHeader(allocator, outer_buf[0..outer_len]));
}

test "decode rejects oversized payload_key_box" {
    const allocator = std.testing.allocator;

    // Build a valid-looking encryption header but with an oversized payload_key_box (>256 bytes).
    var arr = try Payload.arrPayload(6, allocator);

    const name_p = try Payload.strToPayload("saltpack", allocator);
    try arr.setArrElement(0, name_p);

    var ver_arr = try Payload.arrPayload(2, allocator);
    try ver_arr.setArrElement(0, Payload.uintToPayload(2));
    try ver_arr.setArrElement(1, Payload.uintToPayload(0));
    try arr.setArrElement(1, ver_arr);

    try arr.setArrElement(2, Payload.uintToPayload(0)); // encryption

    const eph_p = try Payload.binToPayload(&([_]u8{0} ** 32), allocator);
    try arr.setArrElement(3, eph_p);

    // Valid sender_secretbox.
    const sb_p = try Payload.binToPayload(&([_]u8{0} ** 48), allocator);
    try arr.setArrElement(4, sb_p);

    // Receiver with oversized payload_key_box: 257 bytes.
    var rcv_arr = try Payload.arrPayload(1, allocator);
    var pair = try Payload.arrPayload(2, allocator);
    try pair.setArrElement(0, Payload.nilToPayload());
    const oversized_pkb = try allocator.alloc(u8, 257);
    defer allocator.free(oversized_pkb);
    @memset(oversized_pkb, 0xBB);
    const pkb_p = try Payload.binToPayload(oversized_pkb, allocator);
    try pair.setArrElement(1, pkb_p);
    try rcv_arr.setArrElement(0, pair);
    try arr.setArrElement(5, rcv_arr);

    // Serialize inner array.
    const inner_buf = try allocator.alloc(u8, 65536);
    defer allocator.free(inner_buf);
    var inner_write = fixedBufferStream(inner_buf);
    var inner_dummy_read_storage: [1]u8 = undefined;
    var inner_dummy_read = fixedBufferStream(&inner_dummy_read_storage);
    var inner_packer = MsgPack.init(&inner_write, &inner_dummy_read);
    try inner_packer.write(arr);
    arr.free(allocator);

    const inner_len = inner_write.pos;

    // Wrap as bin.
    const bin_payload = try Payload.binToPayload(inner_buf[0..inner_len], allocator);
    defer bin_payload.free(allocator);

    const outer_buf = try allocator.alloc(u8, inner_len + 16);
    defer allocator.free(outer_buf);
    var outer_write = fixedBufferStream(outer_buf);
    var outer_dummy_read_storage: [1]u8 = undefined;
    var outer_dummy_read = fixedBufferStream(&outer_dummy_read_storage);
    var outer_packer = MsgPack.init(&outer_write, &outer_dummy_read);
    try outer_packer.write(bin_payload);

    const outer_len = outer_write.pos;

    try std.testing.expectError(sp_errors.Error.BadReceivers, decodeHeader(allocator, outer_buf[0..outer_len]));
}

test "decode accepts sender_secretbox and payload_key_box at max size" {
    const allocator = std.testing.allocator;

    // Build an encryption header with exactly 256-byte sender_secretbox and payload_key_box.
    // These should be accepted (at the boundary).
    var arr = try Payload.arrPayload(6, allocator);

    const name_p = try Payload.strToPayload("saltpack", allocator);
    try arr.setArrElement(0, name_p);

    var ver_arr = try Payload.arrPayload(2, allocator);
    try ver_arr.setArrElement(0, Payload.uintToPayload(2));
    try ver_arr.setArrElement(1, Payload.uintToPayload(0));
    try arr.setArrElement(1, ver_arr);

    try arr.setArrElement(2, Payload.uintToPayload(0)); // encryption

    const eph_p = try Payload.binToPayload(&([_]u8{0} ** 32), allocator);
    try arr.setArrElement(3, eph_p);

    // sender_secretbox at exactly 256 bytes.
    const sb_data = try allocator.alloc(u8, 256);
    defer allocator.free(sb_data);
    @memset(sb_data, 0xCC);
    const sb_p = try Payload.binToPayload(sb_data, allocator);
    try arr.setArrElement(4, sb_p);

    // Receiver with payload_key_box at exactly 256 bytes.
    var rcv_arr = try Payload.arrPayload(1, allocator);
    var pair = try Payload.arrPayload(2, allocator);
    try pair.setArrElement(0, Payload.nilToPayload());
    const pkb_data = try allocator.alloc(u8, 256);
    defer allocator.free(pkb_data);
    @memset(pkb_data, 0xDD);
    const pkb_p = try Payload.binToPayload(pkb_data, allocator);
    try pair.setArrElement(1, pkb_p);
    try rcv_arr.setArrElement(0, pair);
    try arr.setArrElement(5, rcv_arr);

    // Serialize inner array.
    const inner_buf = try allocator.alloc(u8, 65536);
    defer allocator.free(inner_buf);
    var inner_write = fixedBufferStream(inner_buf);
    var inner_dummy_read_storage: [1]u8 = undefined;
    var inner_dummy_read = fixedBufferStream(&inner_dummy_read_storage);
    var inner_packer = MsgPack.init(&inner_write, &inner_dummy_read);
    try inner_packer.write(arr);
    arr.free(allocator);

    const inner_len = inner_write.pos;

    // Wrap as bin.
    const bin_payload = try Payload.binToPayload(inner_buf[0..inner_len], allocator);
    defer bin_payload.free(allocator);

    const outer_buf = try allocator.alloc(u8, inner_len + 16);
    defer allocator.free(outer_buf);
    var outer_write = fixedBufferStream(outer_buf);
    var outer_dummy_read_storage: [1]u8 = undefined;
    var outer_dummy_read = fixedBufferStream(&outer_dummy_read_storage);
    var outer_packer = MsgPack.init(&outer_write, &outer_dummy_read);
    try outer_packer.write(bin_payload);

    const outer_len = outer_write.pos;

    // Should succeed (256 is at the boundary, not over).
    const decoded = try decodeHeader(allocator, outer_buf[0..outer_len]);
    switch (decoded) {
        .encryption => |enc| {
            try std.testing.expectEqual(@as(usize, 256), enc.header.sender_secretbox.len);
            try std.testing.expectEqual(@as(usize, 256), enc.header.receivers[0].payload_key_box.len);

            // Free decoded allocations.
            allocator.free(enc.header.sender_secretbox);
            freeDecodedReceivers(allocator, enc.header.receivers);
        },
        .signature => return error.TestUnexpectedResult,
    }
}
