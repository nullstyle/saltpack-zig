//! Saltpack signing (attached and detached) implementation.
//!
//! Zig port of the Go saltpack library's sign.go and sign_stream.go.
//! Implements both attached (mode 1) and detached (mode 2) signatures.

const std = @import("std");
const types = @import("types.zig");
const sp_errors = @import("errors.zig");
const key_mod = @import("key.zig");
const nonce_mod = @import("nonce.zig");
const header_mod = @import("header.zig");

const Sha512 = std.crypto.hash.sha2.Sha512;
const Allocator = std.mem.Allocator;

const mp_utils = @import("msgpack_utils.zig");
const Payload = mp_utils.Payload;
const verify_mod = @import("verify.zig");

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Options for signing operations.
pub const SignOptions = struct {
    version: types.Version = types.Version.v2(),
};

/// Result of a signing operation.
pub const SignResult = struct {
    data: []const u8,
    allocator: Allocator,

    pub fn deinit(self: *const SignResult) void {
        self.allocator.free(self.data);
    }
};

/// Sign creates an attached signature message of plaintext from signer.
/// Returns the signed message bytes (caller owns the returned memory).
pub fn sign(allocator: Allocator, plaintext: []const u8, signer: key_mod.SigningSecretKey, opts: SignOptions) !SignResult {
    const sig_header = header_mod.SignatureHeader{
        .version = opts.version,
        .message_type = .attached_signature,
        .sender_public_key = signer.getPublicKey().bytes,
        .nonce = nonce_mod.generateSignatureNonce(),
    };

    const header_result = try header_mod.encodeSignatureHeader(allocator, sig_header);
    defer allocator.free(header_result.encoded);

    const header_hash = header_result.header_hash;

    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    // Pre-size: header + (plaintext / block_size + 1) * (block_size + 128)
    const num_blocks = if (plaintext.len == 0) 1 else (plaintext.len + types.signature_block_size - 1) / types.signature_block_size;
    const estimated = header_result.encoded.len + num_blocks * (types.signature_block_size + 128) + 256;
    try output.ensureTotalCapacity(allocator, estimated);

    try output.appendSlice(allocator, header_result.encoded);

    const block_size = types.signature_block_size;
    var seqno: u64 = 0;
    var offset: usize = 0;

    switch (opts.version.major) {
        1 => {
            while (offset < plaintext.len) {
                const end = @min(offset + block_size, plaintext.len);
                const chunk = plaintext[offset..end];
                const sig_bytes = try computeAttachedSignature(signer, opts.version, header_hash, chunk, seqno, false);
                try encodeSignatureBlockV1(allocator, &output, &sig_bytes, chunk);
                if (seqno >= types.max_block_number) return sp_errors.Error.PacketOverflow;
                seqno += 1;
                offset = end;
            }
            const empty_chunk: []const u8 = &[_]u8{};
            const final_sig = try computeAttachedSignature(signer, opts.version, header_hash, empty_chunk, seqno, true);
            try encodeSignatureBlockV1(allocator, &output, &final_sig, empty_chunk);
        },
        2 => {
            if (plaintext.len == 0) {
                const empty_chunk: []const u8 = &[_]u8{};
                const sig_bytes = try computeAttachedSignature(signer, opts.version, header_hash, empty_chunk, seqno, true);
                try encodeSignatureBlockV2(allocator, &output, &sig_bytes, empty_chunk, true);
            } else {
                while (offset < plaintext.len) {
                    const end = @min(offset + block_size, plaintext.len);
                    const chunk = plaintext[offset..end];
                    const is_last = (end == plaintext.len);

                    if (!is_last and chunk.len == block_size) {
                        const sig_bytes = try computeAttachedSignature(signer, opts.version, header_hash, chunk, seqno, false);
                        try encodeSignatureBlockV2(allocator, &output, &sig_bytes, chunk, false);
                    } else {
                        const sig_bytes = try computeAttachedSignature(signer, opts.version, header_hash, chunk, seqno, true);
                        try encodeSignatureBlockV2(allocator, &output, &sig_bytes, chunk, true);
                    }
                    if (seqno >= types.max_block_number) return sp_errors.Error.PacketOverflow;
                    seqno += 1;
                    offset = end;
                }
            }
        },
        else => return sp_errors.Error.BadVersion,
    }

    return SignResult{ .data = try output.toOwnedSlice(allocator), .allocator = allocator };
}

/// SignDetached returns a detached signature of plaintext from signer.
pub fn signDetached(allocator: Allocator, plaintext: []const u8, signer: key_mod.SigningSecretKey, opts: SignOptions) !SignResult {
    const sig_header = header_mod.SignatureHeader{
        .version = opts.version,
        .message_type = .detached_signature,
        .sender_public_key = signer.getPublicKey().bytes,
        .nonce = nonce_mod.generateSignatureNonce(),
    };

    const header_result = try header_mod.encodeSignatureHeader(allocator, sig_header);
    defer allocator.free(header_result.encoded);

    const header_hash = header_result.header_hash;

    var hasher = Sha512.init(.{});
    hasher.update(&header_hash);
    hasher.update(plaintext);
    const message_hash = hasher.finalResult();

    var sig_input: [types.signature_detached_string.len + 64]u8 = undefined;
    @memcpy(sig_input[0..types.signature_detached_string.len], types.signature_detached_string);
    @memcpy(sig_input[types.signature_detached_string.len..], &message_hash);

    const signature = try signer.sign(&sig_input);

    var output: std.ArrayList(u8) = .empty;
    errdefer output.deinit(allocator);

    try output.appendSlice(allocator, header_result.encoded);
    try encodeBin(allocator, &output, &signature);

    return SignResult{ .data = try output.toOwnedSlice(allocator), .allocator = allocator };
}

// ---------------------------------------------------------------------------
// Signature computation
// ---------------------------------------------------------------------------

pub fn computeAttachedSignature(
    signer: key_mod.SigningSecretKey,
    version: types.Version,
    header_hash: types.HeaderHash,
    payload_chunk: []const u8,
    seqno: u64,
    is_final: bool,
) ![64]u8 {
    const sig_input = computeAttachedSignatureInput(version, header_hash, payload_chunk, seqno, is_final);
    return try signer.sign(&sig_input);
}

/// Compute the attached signature input bytes (without signing).
pub fn computeAttachedSignatureInput(
    version: types.Version,
    header_hash: types.HeaderHash,
    payload_chunk: []const u8,
    seqno: u64,
    is_final: bool,
) [types.signature_attached_string.len + 64]u8 {
    var hasher = Sha512.init(.{});
    hasher.update(&header_hash);

    var seqno_bytes: [8]u8 = undefined;
    std.mem.writeInt(u64, &seqno_bytes, seqno, .big);
    hasher.update(&seqno_bytes);

    if (version.major == 2) {
        const final_byte: [1]u8 = .{if (is_final) 1 else 0};
        hasher.update(&final_byte);
    }

    hasher.update(payload_chunk);
    const hash = hasher.finalResult();

    var result: [types.signature_attached_string.len + 64]u8 = undefined;
    @memcpy(result[0..types.signature_attached_string.len], types.signature_attached_string);
    @memcpy(result[types.signature_attached_string.len..], &hash);

    return result;
}

// ---------------------------------------------------------------------------
// Msgpack encoding helpers
// ---------------------------------------------------------------------------

fn encodeSignatureBlockV1(allocator: Allocator, output: *std.ArrayList(u8), signature: []const u8, payload_chunk: []const u8) !void {
    var arr = try Payload.arrPayload(2, allocator);
    errdefer arr.free(allocator);

    const sig_payload = try Payload.binToPayload(signature, allocator);
    try arr.setArrElement(0, sig_payload);

    const chunk_payload = try Payload.binToPayload(payload_chunk, allocator);
    try arr.setArrElement(1, chunk_payload);

    try writePayload(allocator, output, arr);
}

fn encodeSignatureBlockV2(allocator: Allocator, output: *std.ArrayList(u8), signature: []const u8, payload_chunk: []const u8, is_final: bool) !void {
    var arr = try Payload.arrPayload(3, allocator);
    errdefer arr.free(allocator);

    try arr.setArrElement(0, Payload.boolToPayload(is_final));

    const sig_payload = try Payload.binToPayload(signature, allocator);
    try arr.setArrElement(1, sig_payload);

    const chunk_payload = try Payload.binToPayload(payload_chunk, allocator);
    try arr.setArrElement(2, chunk_payload);

    try writePayload(allocator, output, arr);
}

fn encodeBin(allocator: Allocator, output: *std.ArrayList(u8), data: []const u8) !void {
    const payload = try Payload.binToPayload(data, allocator);
    try writePayload(allocator, output, payload);
}

fn writePayload(allocator: Allocator, output: *std.ArrayList(u8), payload: Payload) !void {
    const buf_size = 2 * types.signature_block_size + 4096;
    try mp_utils.writePayload(allocator, output, payload, buf_size);
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "sign attached V2 empty message" {
    const allocator = std.testing.allocator;
    const kp = key_mod.SigningKeyPair.generate();
    const result = try sign(allocator, &[_]u8{}, kp.secret_key, .{ .version = types.Version.v2() });
    defer result.deinit();
    try std.testing.expect(result.data.len > 0);

    // Round-trip: verify the signed message and check plaintext matches.
    const verified = try verify_mod.verify(allocator, result.data);
    defer verified.deinit();
    try std.testing.expect(verified.signer.eql(kp.public_key));
    try std.testing.expectEqual(@as(usize, 0), verified.plaintext.len);
}

test "sign attached V1 empty message" {
    const allocator = std.testing.allocator;
    const kp = key_mod.SigningKeyPair.generate();
    const result = try sign(allocator, &[_]u8{}, kp.secret_key, .{ .version = types.Version.v1() });
    defer result.deinit();
    try std.testing.expect(result.data.len > 0);

    // Round-trip: verify the signed message and check plaintext matches.
    const verified = try verify_mod.verify(allocator, result.data);
    defer verified.deinit();
    try std.testing.expect(verified.signer.eql(kp.public_key));
    try std.testing.expectEqual(@as(usize, 0), verified.plaintext.len);
}

test "sign attached V2 short message" {
    const allocator = std.testing.allocator;
    const kp = key_mod.SigningKeyPair.generate();
    const msg = "hello saltpack signing!";
    const result = try sign(allocator, msg, kp.secret_key, .{ .version = types.Version.v2() });
    defer result.deinit();
    try std.testing.expect(result.data.len > 0);

    // Round-trip: verify the signed message and check plaintext matches.
    const verified = try verify_mod.verify(allocator, result.data);
    defer verified.deinit();
    try std.testing.expect(verified.signer.eql(kp.public_key));
    try std.testing.expectEqualSlices(u8, msg, verified.plaintext);
}

test "sign detached V2" {
    const allocator = std.testing.allocator;
    const kp = key_mod.SigningKeyPair.generate();
    const msg = "hello detached";
    const result = try signDetached(allocator, msg, kp.secret_key, .{ .version = types.Version.v2() });
    defer result.deinit();
    try std.testing.expect(result.data.len > 0);

    // Round-trip: verify the detached signature against the original message.
    const verified = try verify_mod.verifyDetached(allocator, msg, result.data);
    defer verified.deinit();
    try std.testing.expect(verified.signer.eql(kp.public_key));
}

test "sign detached V1" {
    const allocator = std.testing.allocator;
    const kp = key_mod.SigningKeyPair.generate();
    const msg = "hello detached v1";
    const result = try signDetached(allocator, msg, kp.secret_key, .{ .version = types.Version.v1() });
    defer result.deinit();
    try std.testing.expect(result.data.len > 0);

    // Round-trip: verify the detached signature against the original message.
    const verified = try verify_mod.verifyDetached(allocator, msg, result.data);
    defer verified.deinit();
    try std.testing.expect(verified.signer.eql(kp.public_key));
}

test "computeAttachedSignatureInput produces deterministic output" {
    const header_hash = [_]u8{0xAA} ** 64;
    const chunk = "test chunk";
    const input1 = computeAttachedSignatureInput(types.Version.v2(), header_hash, chunk, 0, false);
    const input2 = computeAttachedSignatureInput(types.Version.v2(), header_hash, chunk, 0, false);
    try std.testing.expectEqualSlices(u8, &input1, &input2);
}

test "computeAttachedSignatureInput differs for v1 vs v2" {
    const header_hash = [_]u8{0xAA} ** 64;
    const chunk = "test chunk";
    const input_v1 = computeAttachedSignatureInput(types.Version.v1(), header_hash, chunk, 0, false);
    const input_v2 = computeAttachedSignatureInput(types.Version.v2(), header_hash, chunk, 0, false);
    try std.testing.expect(!std.mem.eql(u8, &input_v1, &input_v2));
}

test "computeAttachedSignatureInput differs for different seqno" {
    const header_hash = [_]u8{0xAA} ** 64;
    const chunk = "test chunk";
    const input0 = computeAttachedSignatureInput(types.Version.v2(), header_hash, chunk, 0, false);
    const input1 = computeAttachedSignatureInput(types.Version.v2(), header_hash, chunk, 1, false);
    try std.testing.expect(!std.mem.eql(u8, &input0, &input1));
}

test "computeAttachedSignatureInput differs for final flag" {
    const header_hash = [_]u8{0xAA} ** 64;
    const chunk = "test chunk";
    const input_nonfinal = computeAttachedSignatureInput(types.Version.v2(), header_hash, chunk, 0, false);
    const input_final = computeAttachedSignatureInput(types.Version.v2(), header_hash, chunk, 0, true);
    try std.testing.expect(!std.mem.eql(u8, &input_nonfinal, &input_final));
}
