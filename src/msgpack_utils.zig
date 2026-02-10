//! Shared msgpack utility module for saltpack.
//!
//! Provides the common MsgPack type alias, buffer creation helpers,
//! and shared encoding/decoding functions used across sign, encrypt,
//! decrypt, signcrypt, header, and verify modules.

const std = @import("std");
const msgpack = @import("msgpack");
const types = @import("types.zig");
const sp_errors = @import("errors.zig");
const header_mod = @import("header.zig");

const Allocator = std.mem.Allocator;

// ---------------------------------------------------------------------------
// Re-exported msgpack compatibility types
// ---------------------------------------------------------------------------

pub const compat = msgpack.compat;
pub const BufferStream = compat.BufferStream;
pub const fixedBufferStream = compat.fixedBufferStream;
pub const Payload = msgpack.Payload;

// ---------------------------------------------------------------------------
// Common MsgPack type alias
// ---------------------------------------------------------------------------

/// The standard MsgPack packer/unpacker type used throughout saltpack,
/// parameterized on BufferStream for both reading and writing.
pub const MsgPack = msgpack.Pack(
    *BufferStream,
    *BufferStream,
    BufferStream.WriteError,
    BufferStream.ReadError,
    BufferStream.write,
    BufferStream.read,
);

// ---------------------------------------------------------------------------
// Packer creation helpers
// ---------------------------------------------------------------------------

/// Create a MsgPack writer (for encoding). The caller provides the write buffer;
/// a dummy read buffer is created internally.
/// Returns the packer and the dummy read storage (which must remain alive).
pub const WritePacker = struct {
    packer: MsgPack,
    dummy_read_storage: [1]u8,
    dummy_read: BufferStream,

    pub fn init(write_buf: *BufferStream) WritePacker {
        var result = WritePacker{
            .packer = undefined,
            .dummy_read_storage = undefined,
            .dummy_read = undefined,
        };
        result.dummy_read = fixedBufferStream(&result.dummy_read_storage);
        result.packer = MsgPack.init(write_buf, &result.dummy_read);
        return result;
    }
};

/// Create a MsgPack reader (for decoding). The caller provides the read buffer;
/// a dummy write buffer is created internally.
pub const ReadPacker = struct {
    packer: MsgPack,
    dummy_write_storage: [1]u8,
    dummy_write: BufferStream,

    pub fn init(read_buf: *BufferStream) ReadPacker {
        var result = ReadPacker{
            .packer = undefined,
            .dummy_write_storage = undefined,
            .dummy_write = undefined,
        };
        result.dummy_write = fixedBufferStream(&result.dummy_write_storage);
        result.packer = MsgPack.init(&result.dummy_write, read_buf);
        return result;
    }
};

// ---------------------------------------------------------------------------
// Shared encoding helpers
// ---------------------------------------------------------------------------

/// Encode a msgpack Payload and append the serialized bytes to an output ArrayList.
///
/// This function is used by sign.zig, encrypt.zig, and other modules to serialize
/// payload blocks. The payload is freed after writing.
///
/// `buf_size` controls the temporary buffer size for serialization. Callers should
/// pass a size large enough for the expected payload (e.g. 2 * block_size + 4096).
pub fn writePayload(allocator: Allocator, output: *std.ArrayList(u8), payload: Payload, buf_size: usize) !void {
    defer {
        var p = payload;
        p.free(allocator);
    }

    const buf_storage = try allocator.alloc(u8, buf_size);
    defer allocator.free(buf_storage);
    var write_buf = fixedBufferStream(buf_storage);
    var dummy_read_storage: [1]u8 = undefined;
    var dummy_read = fixedBufferStream(&dummy_read_storage);

    var packer = MsgPack.init(&write_buf, &dummy_read);
    try packer.write(payload);

    const written = buf_storage[0..write_buf.pos];
    try output.appendSlice(allocator, written);
}

/// Encode a msgpack Payload and return the serialized bytes as a newly allocated slice.
///
/// The payload is freed after writing. The caller owns the returned slice.
///
/// `buf_size` controls the temporary buffer size for serialization.
pub fn encodePayload(allocator: Allocator, payload: Payload, buf_size: usize) ![]u8 {
    defer {
        var p = payload;
        p.free(allocator);
    }

    const buf_storage = try allocator.alloc(u8, buf_size);
    defer allocator.free(buf_storage);
    var write_buf = fixedBufferStream(buf_storage);
    var dummy_read_storage: [1]u8 = undefined;
    var dummy_read = fixedBufferStream(&dummy_read_storage);

    var packer = MsgPack.init(&write_buf, &dummy_read);
    try packer.write(payload);

    const len = write_buf.pos;
    const result = try allocator.alloc(u8, len);
    @memcpy(result, buf_storage[0..len]);
    return result;
}

// ---------------------------------------------------------------------------
// Shared decoding helpers
// ---------------------------------------------------------------------------

/// Result of decoding an encryption/signcryption header from a byte stream.
pub const HeaderDecodeResult = struct {
    header: header_mod.EncryptionHeader,
    header_hash: types.HeaderHash,
    bytes_consumed: usize,
};

/// Decode an encryption or signcryption header from the front of a byte stream.
///
/// This is used by both decrypt.zig and signcrypt.zig. It reads the outer msgpack
/// value to determine how many bytes the header consumes, then delegates to
/// header_mod.decodeHeader for the actual parsing.
pub fn decodeHeaderFromStream(allocator: Allocator, data: []const u8) !HeaderDecodeResult {
    // Maximum header size must accommodate up to max_receiver_count receivers.
    // Each receiver contributes roughly 120-150 bytes in msgpack encoding (32-byte KID +
    // ~80-byte payload_key_box + framing). We use a generous 256-byte per-receiver
    // estimate plus 1024 bytes for the base header fields and double-encoding overhead.
    const max_header_size: usize = 1024 + types.max_receiver_count * 256;
    const buf_len = @min(data.len, max_header_size);
    const read_buf_storage = try allocator.alloc(u8, buf_len);
    defer allocator.free(read_buf_storage);
    @memcpy(read_buf_storage, data[0..buf_len]);
    var read_buf = fixedBufferStream(read_buf_storage);

    var dummy_write_storage: [1]u8 = undefined;
    var dummy_write = fixedBufferStream(&dummy_write_storage);
    var packer = MsgPack.init(&dummy_write, &read_buf);

    const outer_payload = packer.read(allocator) catch {
        return sp_errors.Error.FailedToReadHeaderBytes;
    };
    defer outer_payload.free(allocator);

    const bytes_consumed = read_buf.pos;

    const decoded = header_mod.decodeHeader(allocator, data[0..bytes_consumed]) catch {
        return sp_errors.Error.FailedToReadHeaderBytes;
    };

    switch (decoded) {
        .encryption => |enc| {
            return HeaderDecodeResult{
                .header = enc.header,
                .header_hash = enc.hash,
                .bytes_consumed = bytes_consumed,
            };
        },
        .signature => {
            return sp_errors.Error.WrongMessageType;
        },
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "writePayload round-trip: write bin payload then read it back" {
    const allocator = std.testing.allocator;
    const test_data = "hello msgpack utils";

    // Create a bin payload and write it to an ArrayList.
    const payload = try Payload.binToPayload(test_data, allocator);
    var output: std.ArrayList(u8) = .empty;
    defer output.deinit(allocator);
    try writePayload(allocator, &output, payload, 4096);

    // Read it back using a MsgPack reader.
    const read_storage = try allocator.alloc(u8, output.items.len);
    defer allocator.free(read_storage);
    @memcpy(read_storage, output.items);
    var read_buf = fixedBufferStream(read_storage);
    var dummy_write_storage: [1]u8 = undefined;
    var dummy_write = fixedBufferStream(&dummy_write_storage);
    var packer = MsgPack.init(&dummy_write, &read_buf);

    const result = try packer.read(allocator);
    defer result.free(allocator);

    const result_bytes = switch (result) {
        .bin => |b| b.bin,
        else => unreachable,
    };
    try std.testing.expectEqualSlices(u8, test_data, result_bytes);
}

test "encodePayload produces valid msgpack bytes" {
    const allocator = std.testing.allocator;

    // Encode a uint payload.
    const payload = Payload.uintToPayload(42);
    const encoded = try encodePayload(allocator, payload, 256);
    defer allocator.free(encoded);

    // The encoded output should be non-empty valid msgpack.
    try std.testing.expect(encoded.len > 0);

    // Read it back and verify the value.
    const read_storage = try allocator.alloc(u8, encoded.len);
    defer allocator.free(read_storage);
    @memcpy(read_storage, encoded);
    var read_buf = fixedBufferStream(read_storage);
    var dummy_write_storage: [1]u8 = undefined;
    var dummy_write = fixedBufferStream(&dummy_write_storage);
    var packer = MsgPack.init(&dummy_write, &read_buf);

    const result = try packer.read(allocator);
    defer result.free(allocator);

    const value = switch (result) {
        .uint => |v| v,
        else => unreachable,
    };
    try std.testing.expectEqual(@as(u64, 42), value);
}

test "decodeHeaderFromStream with valid double-encoded encryption header" {
    const allocator = std.testing.allocator;

    // Build a minimal valid encryption header.
    const ephemeral_key = [_]u8{0x01} ** 32;
    const sender_secretbox = [_]u8{0x02} ** 48;
    const kid = [_]u8{0x03} ** 32;
    const pkb = [_]u8{0x04} ** 48;

    const receivers = [_]header_mod.ReceiverKeys{
        .{
            .recipient_kid = &kid,
            .payload_key_box = &pkb,
        },
    };

    const header = header_mod.EncryptionHeader{
        .version = types.Version.v2(),
        .message_type = .encryption,
        .ephemeral_key = ephemeral_key,
        .sender_secretbox = &sender_secretbox,
        .receivers = &receivers,
    };

    const header_result = try header_mod.encodeEncryptionHeader(allocator, header);
    defer allocator.free(header_result.encoded);

    // Append some trailing data to simulate a message stream.
    const stream = try allocator.alloc(u8, header_result.encoded.len + 10);
    defer allocator.free(stream);
    @memcpy(stream[0..header_result.encoded.len], header_result.encoded);
    @memset(stream[header_result.encoded.len..], 0xCC);

    // Decode the header from the stream.
    const decoded = try decodeHeaderFromStream(allocator, stream);
    defer {
        allocator.free(decoded.header.sender_secretbox);
        header_mod.freeDecodedReceivers(allocator, decoded.header.receivers);
    }

    try std.testing.expect(decoded.header.version.eql(types.Version.v2()));
    try std.testing.expectEqual(types.MessageType.encryption, decoded.header.message_type);
    try std.testing.expectEqualSlices(u8, &ephemeral_key, &decoded.header.ephemeral_key);
    try std.testing.expectEqual(header_result.encoded.len, decoded.bytes_consumed);
}

test "decodeHeaderFromStream with truncated input returns error" {
    const allocator = std.testing.allocator;

    // Provide a few bytes that do not form a valid msgpack bin header.
    // This should fail with FailedToReadHeaderBytes.
    const truncated = [_]u8{ 0xC4, 0xFF }; // bin8 header claiming 255 bytes, but only 2 bytes present
    try std.testing.expectError(
        sp_errors.Error.FailedToReadHeaderBytes,
        decodeHeaderFromStream(allocator, &truncated),
    );
}

test "decodeHeaderFromStream with empty input returns error" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(
        sp_errors.Error.FailedToReadHeaderBytes,
        decodeHeaderFromStream(allocator, ""),
    );
}
