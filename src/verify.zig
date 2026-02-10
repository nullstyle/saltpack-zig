//! Saltpack signature verification implementation.
//!
//! Zig port of the Go saltpack library's verify.go and verify_stream.go.
//! Implements verification for both attached (mode 1) and detached (mode 2) signatures.

const std = @import("std");
const types = @import("types.zig");
const sp_errors = @import("errors.zig");
const key_mod = @import("key.zig");
const header_mod = @import("header.zig");
const sign_mod = @import("sign.zig");

const Sha512 = std.crypto.hash.sha2.Sha512;
const Allocator = std.mem.Allocator;

const mp_utils = @import("msgpack_utils.zig");
const MsgPack = mp_utils.MsgPack;
const BufferStream = mp_utils.BufferStream;
const fixedBufferStream = mp_utils.fixedBufferStream;
const Payload = mp_utils.Payload;

// ---------------------------------------------------------------------------
// Public API
// ---------------------------------------------------------------------------

/// Result of verification: the signer's public key and the verified plaintext.
pub const VerifyResult = struct {
    signer: key_mod.SigningPublicKey,
    plaintext: []const u8,
    allocator: Allocator,

    pub fn deinit(self: *const VerifyResult) void {
        self.allocator.free(self.plaintext);
    }
};

/// Result of detached verification: just the signer's public key.
pub const VerifyDetachedResult = struct {
    signer: key_mod.SigningPublicKey,

    /// No-op deinit for API consistency with `VerifyResult`.
    /// `VerifyDetachedResult` holds no heap allocations, so there is nothing to free.
    pub fn deinit(_: *const VerifyDetachedResult) void {}
};

/// Options for verify and verifyDetached.
///
/// All fields are optional and default to null, which preserves the original
/// "accept anything" behavior. Callers can restrict accepted signers and/or
/// protocol versions by providing non-null values.
pub const VerifyOptions = struct {
    /// When non-null, only signers whose public key appears in this slice
    /// will be accepted. If the message was signed by a key not in this set,
    /// verification fails with `error.UntrustedSigner`.
    trusted_signers: ?[]const key_mod.SigningPublicKey = null,

    /// When non-null, only protocol versions allowed by this policy will be
    /// accepted. If the message's version is not allowed, verification fails
    /// with `error.VersionNotAllowed`.
    version_policy: ?types.VersionPolicy = null,
};

/// Verify checks an attached signature message.
/// Returns the signer's public key and verified plaintext.
/// This is the backward-compatible entry point (accepts any signer, any version).
///
/// WARNING: This function does NOT authenticate the signer's identity. The
/// returned `signer` is the public key embedded in the message header -- any
/// party can construct a valid signed message with a key they control. To
/// verify the signer is trusted, use `verifyWithOptions` with `trusted_signers`.
///
/// **Ownership:** The caller owns the returned `VerifyResult` and must call
/// `result.deinit()` to free the verified plaintext.
pub fn verify(allocator: Allocator, signed_msg: []const u8) !VerifyResult {
    return verifyWithOptions(allocator, signed_msg, .{});
}

/// Verify checks an attached signature message with caller-specified options.
/// Use `opts.trusted_signers` to restrict which signing keys are accepted and
/// `opts.version_policy` to restrict which protocol versions are allowed.
///
/// **Memory note:** This function copies the entire `signed_msg` to the heap
/// because the underlying msgpack parser requires a mutable buffer. For large
/// messages this effectively doubles peak memory usage. Consider using
/// `VerifyStream` for large inputs to avoid the extra copy.
pub fn verifyWithOptions(allocator: Allocator, signed_msg: []const u8, opts: VerifyOptions) !VerifyResult {
    // We need a read buffer for msgpack parsing.
    // Use heap allocation for large messages. This copies the entire input,
    // which doubles peak memory for large messages. VerifyStream avoids this.
    const buf_len = signed_msg.len;
    const read_storage = try allocator.alloc(u8, buf_len);
    defer allocator.free(read_storage);
    @memcpy(read_storage, signed_msg);

    var read_buf = fixedBufferStream(read_storage);
    var dummy_write_storage: [1]u8 = undefined;
    var dummy_write = fixedBufferStream(&dummy_write_storage);
    var packer = MsgPack.init(&dummy_write, &read_buf);

    // Step 1: Read the outer header (double-encoded: a bin containing the header array).
    const outer_payload = packer.read(allocator) catch {
        return sp_errors.Error.FailedToReadHeaderBytes;
    };
    defer outer_payload.free(allocator);

    const header_bytes: []const u8 = switch (outer_payload) {
        .bin => |b| b.bin,
        else => return sp_errors.Error.FailedToReadHeaderBytes,
    };

    // Compute header hash.
    var header_hash: types.HeaderHash = undefined;
    Sha512.hash(header_bytes, &header_hash, .{});

    // Decode the header.
    const decoded = header_mod.decodeHeader(allocator, signed_msg[0..read_buf.pos]) catch {
        return sp_errors.Error.FailedToReadHeaderBytes;
    };

    const sig_info = switch (decoded) {
        .signature => |s| s,
        .encryption => |enc| {
            allocator.free(enc.header.sender_secretbox);
            header_mod.freeDecodedReceivers(allocator, enc.header.receivers);
            return sp_errors.Error.WrongMessageType;
        },
    };

    // Validate message type.
    if (sig_info.header.message_type != .attached_signature) {
        return sp_errors.Error.WrongMessageType;
    }

    const version = sig_info.header.version;
    const sender_pk = try key_mod.SigningPublicKey.fromBytes(sig_info.header.sender_public_key);

    // Check version policy.
    if (opts.version_policy) |policy| {
        if (!policy.allows(version)) {
            return sp_errors.Error.VersionNotAllowed;
        }
    }

    // Check trusted signers.
    if (opts.trusted_signers) |trusted| {
        var found = false;
        for (trusted) |t| {
            if (t.eql(sender_pk)) {
                found = true;
                break;
            }
        }
        if (!found) {
            return sp_errors.Error.UntrustedSigner;
        }
    }

    // Step 2: Read and verify payload blocks.
    var plaintext_builder: std.ArrayList(u8) = .empty;
    errdefer plaintext_builder.deinit(allocator);

    try plaintext_builder.ensureTotalCapacity(allocator, signed_msg.len);

    var seqno: u64 = 0;
    var found_final = false;

    while (!found_final) {
        // Read the next payload block.
        const block_payload = packer.read(allocator) catch {
            return sp_errors.Error.TruncatedMessage;
        };
        defer block_payload.free(allocator);

        const block_arr = switch (block_payload) {
            .arr => |a| a,
            else => return sp_errors.Error.BadSignature,
        };

        var is_final: bool = undefined;
        var signature_slice: []const u8 = undefined;
        var payload_chunk: []const u8 = undefined;

        switch (version.major) {
            1 => {
                // V1: [signature, payload_chunk]
                if (block_arr.len != 2) return sp_errors.Error.BadSignature;

                signature_slice = switch (block_arr[0]) {
                    .bin => |b| b.bin,
                    else => return sp_errors.Error.BadSignature,
                };

                payload_chunk = switch (block_arr[1]) {
                    .bin => |b| b.bin,
                    else => return sp_errors.Error.BadSignature,
                };

                // In V1, final is determined by empty payload.
                is_final = (payload_chunk.len == 0);
            },
            2 => {
                // V2: [is_final, signature, payload_chunk]
                if (block_arr.len != 3) return sp_errors.Error.BadSignature;

                is_final = switch (block_arr[0]) {
                    .bool => |b| b,
                    else => return sp_errors.Error.BadSignature,
                };

                signature_slice = switch (block_arr[1]) {
                    .bin => |b| b.bin,
                    else => return sp_errors.Error.BadSignature,
                };

                payload_chunk = switch (block_arr[2]) {
                    .bin => |b| b.bin,
                    else => return sp_errors.Error.BadSignature,
                };
            },
            else => return sp_errors.Error.BadVersion,
        }

        // Validate signature length.
        if (signature_slice.len != 64) return sp_errors.Error.BadSignature;
        var sig_bytes: [64]u8 = undefined;
        @memcpy(&sig_bytes, signature_slice);

        // Verify the block's signature.
        const sig_input = sign_mod.computeAttachedSignatureInput(
            version,
            header_hash,
            payload_chunk,
            seqno,
            is_final,
        );

        sender_pk.verify(&sig_input, sig_bytes) catch {
            return sp_errors.Error.BadSignature;
        };

        // Check for unexpected empty blocks (V2 specific).
        if (version.major == 2) {
            if (payload_chunk.len == 0 and (seqno != 0 or !is_final)) {
                return sp_errors.Error.UnexpectedEmptyBlock;
            }
        }

        // Accumulate plaintext.
        if (payload_chunk.len > 0) {
            try plaintext_builder.appendSlice(allocator, payload_chunk);
        }

        if (is_final) {
            found_final = true;
        }

        if (seqno >= types.max_block_number) return sp_errors.Error.PacketOverflow;
        seqno += 1;
    }

    // Check for trailing garbage.
    // Try to read one more element -- if there is one, it's an error.
    if (packer.read(allocator)) |trailing| {
        // If we get here, there was trailing data.
        trailing.free(allocator);
        return sp_errors.Error.TrailingGarbage;
    } else |_| {
        // Expected: we should get an error because there's nothing left.
        // Good -- no trailing data.
    }

    const result_plaintext = try plaintext_builder.toOwnedSlice(allocator);

    return VerifyResult{
        .signer = sender_pk,
        .plaintext = result_plaintext,
        .allocator = allocator,
    };
}

/// VerifyDetached verifies a detached signature against a message.
/// Returns the signer's public key if verification succeeds.
/// This is the backward-compatible entry point (accepts any signer, any version).
///
/// WARNING: This function does NOT authenticate the signer's identity. The
/// returned `signer` is the public key embedded in the signature header -- any
/// party can create a valid detached signature with a key they control. To
/// verify the signer is trusted, use `verifyDetachedWithOptions` with `trusted_signers`.
pub fn verifyDetached(allocator: Allocator, message: []const u8, signature_msg: []const u8) !VerifyDetachedResult {
    return verifyDetachedWithOptions(allocator, message, signature_msg, .{});
}

/// VerifyDetached verifies a detached signature with caller-specified options.
/// Use `opts.trusted_signers` to restrict which signing keys are accepted and
/// `opts.version_policy` to restrict which protocol versions are allowed.
pub fn verifyDetachedWithOptions(allocator: Allocator, message: []const u8, signature_msg: []const u8, opts: VerifyOptions) !VerifyDetachedResult {
    // Parse the signature message (header + signature).
    const buf_len = signature_msg.len;
    const read_storage = try allocator.alloc(u8, buf_len);
    defer allocator.free(read_storage);
    @memcpy(read_storage, signature_msg);

    var read_buf = fixedBufferStream(read_storage);
    var dummy_write_storage: [1]u8 = undefined;
    var dummy_write = fixedBufferStream(&dummy_write_storage);
    var packer = MsgPack.init(&dummy_write, &read_buf);

    // Step 1: Read the outer header.
    const outer_payload = packer.read(allocator) catch {
        return sp_errors.Error.FailedToReadHeaderBytes;
    };
    defer outer_payload.free(allocator);

    const header_bytes: []const u8 = switch (outer_payload) {
        .bin => |b| b.bin,
        else => return sp_errors.Error.FailedToReadHeaderBytes,
    };

    // Compute header hash.
    var header_hash: types.HeaderHash = undefined;
    Sha512.hash(header_bytes, &header_hash, .{});

    // Decode the header.
    const decoded = header_mod.decodeHeader(allocator, signature_msg[0..read_buf.pos]) catch {
        return sp_errors.Error.FailedToReadHeaderBytes;
    };

    const sig_info = switch (decoded) {
        .signature => |s| s,
        .encryption => |enc| {
            allocator.free(enc.header.sender_secretbox);
            header_mod.freeDecodedReceivers(allocator, enc.header.receivers);
            return sp_errors.Error.WrongMessageType;
        },
    };

    if (sig_info.header.message_type != .detached_signature) {
        return sp_errors.Error.WrongMessageType;
    }

    const sender_pk = try key_mod.SigningPublicKey.fromBytes(sig_info.header.sender_public_key);

    // Check version policy.
    if (opts.version_policy) |policy| {
        if (!policy.allows(sig_info.header.version)) {
            return sp_errors.Error.VersionNotAllowed;
        }
    }

    // Check trusted signers.
    if (opts.trusted_signers) |trusted| {
        var found = false;
        for (trusted) |t| {
            if (t.eql(sender_pk)) {
                found = true;
                break;
            }
        }
        if (!found) {
            return sp_errors.Error.UntrustedSigner;
        }
    }

    // Step 2: Read the signature.
    const sig_payload = packer.read(allocator) catch {
        return sp_errors.Error.TruncatedMessage;
    };
    defer sig_payload.free(allocator);

    const sig_slice: []const u8 = switch (sig_payload) {
        .bin => |b| b.bin,
        else => return sp_errors.Error.BadSignature,
    };

    if (sig_slice.len != 64) return sp_errors.Error.BadSignature;
    var sig_bytes: [64]u8 = undefined;
    @memcpy(&sig_bytes, sig_slice);

    // Step 3: Compute the expected signature input.
    // Hash: SHA-512(headerHash || message)
    var hasher = Sha512.init(.{});
    hasher.update(&header_hash);
    hasher.update(message);
    const message_hash = hasher.finalResult();

    // Signature input: signatureDetachedString || messageHash
    var sig_input: [types.signature_detached_string.len + 64]u8 = undefined;
    @memcpy(sig_input[0..types.signature_detached_string.len], types.signature_detached_string);
    @memcpy(sig_input[types.signature_detached_string.len..], &message_hash);

    // Step 4: Verify.
    sender_pk.verify(&sig_input, sig_bytes) catch {
        return sp_errors.Error.BadSignature;
    };

    return VerifyDetachedResult{ .signer = sender_pk };
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "sign and verify attached V2 empty message" {
    const allocator = std.testing.allocator;
    const kp = key_mod.SigningKeyPair.generate();

    const signed = try sign_mod.sign(allocator, &[_]u8{}, kp.secret_key, .{ .version = types.Version.v2() });
    defer signed.deinit();

    const result = try verify(allocator, signed.data);
    defer result.deinit();

    try std.testing.expect(result.signer.eql(kp.public_key));
    try std.testing.expectEqual(@as(usize, 0), result.plaintext.len);
}

test "sign and verify attached V1 empty message" {
    const allocator = std.testing.allocator;
    const kp = key_mod.SigningKeyPair.generate();

    const signed = try sign_mod.sign(allocator, &[_]u8{}, kp.secret_key, .{ .version = types.Version.v1() });
    defer signed.deinit();

    const result = try verify(allocator, signed.data);
    defer result.deinit();

    try std.testing.expect(result.signer.eql(kp.public_key));
    try std.testing.expectEqual(@as(usize, 0), result.plaintext.len);
}

test "sign and verify attached V2 short message" {
    const allocator = std.testing.allocator;
    const kp = key_mod.SigningKeyPair.generate();
    const msg = "hello saltpack!";

    const signed = try sign_mod.sign(allocator, msg, kp.secret_key, .{ .version = types.Version.v2() });
    defer signed.deinit();

    const result = try verify(allocator, signed.data);
    defer result.deinit();

    try std.testing.expect(result.signer.eql(kp.public_key));
    try std.testing.expectEqualSlices(u8, msg, result.plaintext);
}

test "sign and verify attached V1 short message" {
    const allocator = std.testing.allocator;
    const kp = key_mod.SigningKeyPair.generate();
    const msg = "hello saltpack v1!";

    const signed = try sign_mod.sign(allocator, msg, kp.secret_key, .{ .version = types.Version.v1() });
    defer signed.deinit();

    const result = try verify(allocator, signed.data);
    defer result.deinit();

    try std.testing.expect(result.signer.eql(kp.public_key));
    try std.testing.expectEqualSlices(u8, msg, result.plaintext);
}

test "sign and verify attached V2 medium message (10KB)" {
    const allocator = std.testing.allocator;
    const kp = key_mod.SigningKeyPair.generate();
    const msg = [_]u8{0x42} ** (10 * 1024);

    const signed = try sign_mod.sign(allocator, &msg, kp.secret_key, .{ .version = types.Version.v2() });
    defer signed.deinit();

    const result = try verify(allocator, signed.data);
    defer result.deinit();

    try std.testing.expect(result.signer.eql(kp.public_key));
    try std.testing.expectEqualSlices(u8, &msg, result.plaintext);
}

test "sign and verify detached V2" {
    const allocator = std.testing.allocator;
    const kp = key_mod.SigningKeyPair.generate();
    const msg = "hello detached!";

    const sig_result = try sign_mod.signDetached(allocator, msg, kp.secret_key, .{ .version = types.Version.v2() });
    defer sig_result.deinit();

    const result = try verifyDetached(allocator, msg, sig_result.data);

    try std.testing.expect(result.signer.eql(kp.public_key));
}

test "sign and verify detached V1" {
    const allocator = std.testing.allocator;
    const kp = key_mod.SigningKeyPair.generate();
    const msg = "hello detached v1!";

    const sig_result = try sign_mod.signDetached(allocator, msg, kp.secret_key, .{ .version = types.Version.v1() });
    defer sig_result.deinit();

    const result = try verifyDetached(allocator, msg, sig_result.data);

    try std.testing.expect(result.signer.eql(kp.public_key));
}

test "verify attached tampered payload fails" {
    const allocator = std.testing.allocator;
    const kp = key_mod.SigningKeyPair.generate();
    const msg = "hello saltpack!";

    const signed = try sign_mod.sign(allocator, msg, kp.secret_key, .{ .version = types.Version.v2() });
    defer signed.deinit();

    // Tamper with the last byte of the signed message.
    const tampered = try allocator.alloc(u8, signed.data.len);
    defer allocator.free(tampered);
    @memcpy(tampered, signed.data);
    tampered[tampered.len - 1] ^= 0xFF;

    const result = verify(allocator, tampered);
    try std.testing.expectError(sp_errors.Error.BadSignature, result);
}

test "verify detached tampered message fails" {
    const allocator = std.testing.allocator;
    const kp = key_mod.SigningKeyPair.generate();
    const msg = "hello detached!";

    const sig_result = try sign_mod.signDetached(allocator, msg, kp.secret_key, .{ .version = types.Version.v2() });
    defer sig_result.deinit();

    // Verify with different message should fail.
    const wrong_msg = "wrong message!";
    const result = verifyDetached(allocator, wrong_msg, sig_result.data);
    try std.testing.expectError(sp_errors.Error.BadSignature, result);
}

test "verify detached with wrong key fails" {
    const allocator = std.testing.allocator;
    const kp1 = key_mod.SigningKeyPair.generate();
    const kp2 = key_mod.SigningKeyPair.generate();
    const msg = "hello!";

    // Sign with kp1.
    const sig_result = try sign_mod.signDetached(allocator, msg, kp1.secret_key, .{ .version = types.Version.v2() });
    defer sig_result.deinit();

    // The verification uses the sender key embedded in the header (kp1),
    // not kp2. Since the header has the correct key and the signature is valid,
    // it should succeed. But the returned signer should be kp1, not kp2.
    const result = try verifyDetached(allocator, msg, sig_result.data);
    try std.testing.expect(result.signer.eql(kp1.public_key));
    try std.testing.expect(!result.signer.eql(kp2.public_key));
}

test "verify detached verifying attached message fails with WrongMessageType" {
    const allocator = std.testing.allocator;
    const kp = key_mod.SigningKeyPair.generate();
    const msg = "hello!";

    // Create an attached signature.
    const signed = try sign_mod.sign(allocator, msg, kp.secret_key, .{ .version = types.Version.v2() });
    defer signed.deinit();

    // Try to verify as detached -- should fail with WrongMessageType.
    const result = verifyDetached(allocator, msg, signed.data);
    try std.testing.expectError(sp_errors.Error.WrongMessageType, result);
}

test "verify attached verifying detached message fails with WrongMessageType" {
    const allocator = std.testing.allocator;
    const kp = key_mod.SigningKeyPair.generate();
    const msg = "hello!";

    // Create a detached signature.
    const sig_result = try sign_mod.signDetached(allocator, msg, kp.secret_key, .{ .version = types.Version.v2() });
    defer sig_result.deinit();

    // Try to verify as attached -- should fail with WrongMessageType.
    const result = verify(allocator, sig_result.data);
    try std.testing.expectError(sp_errors.Error.WrongMessageType, result);
}

test "sign and verify multiple message sizes V2" {
    const allocator = std.testing.allocator;
    const kp = key_mod.SigningKeyPair.generate();

    const sizes = [_]usize{ 0, 1, 10, 128, 1024, 4096, 10240 };

    for (sizes) |size| {
        const msg = try allocator.alloc(u8, size);
        defer allocator.free(msg);
        @memset(msg, 0x55);

        const signed = try sign_mod.sign(allocator, msg, kp.secret_key, .{ .version = types.Version.v2() });
        defer signed.deinit();

        const result = try verify(allocator, signed.data);
        defer result.deinit();

        try std.testing.expect(result.signer.eql(kp.public_key));
        try std.testing.expectEqualSlices(u8, msg, result.plaintext);
    }
}

test "sign and verify multiple message sizes V1" {
    const allocator = std.testing.allocator;
    const kp = key_mod.SigningKeyPair.generate();

    const sizes = [_]usize{ 0, 1, 10, 128, 1024, 4096, 10240 };

    for (sizes) |size| {
        const msg = try allocator.alloc(u8, size);
        defer allocator.free(msg);
        @memset(msg, 0x55);

        const signed = try sign_mod.sign(allocator, msg, kp.secret_key, .{ .version = types.Version.v1() });
        defer signed.deinit();

        const result = try verify(allocator, signed.data);
        defer result.deinit();

        try std.testing.expect(result.signer.eql(kp.public_key));
        try std.testing.expectEqualSlices(u8, msg, result.plaintext);
    }
}

test "verify truncated signed message fails" {
    const allocator = std.testing.allocator;
    const kp = key_mod.SigningKeyPair.generate();
    const msg = "this message will be truncated after signing";

    const signed = try sign_mod.sign(allocator, msg, kp.secret_key, .{ .version = types.Version.v2() });
    defer signed.deinit();

    // Keep only the first 60 bytes (enough for the header, but not enough
    // data for a valid payload block). This ensures the block read itself
    // fails, producing a clean TruncatedMessage error without partial allocations.
    const truncated_len = @min(signed.data.len, 60);
    const truncated = try allocator.alloc(u8, truncated_len);
    defer allocator.free(truncated);
    @memcpy(truncated, signed.data[0..truncated_len]);

    const result = verify(allocator, truncated);
    try std.testing.expect(std.meta.isError(result));
}

test "verify rejects encrypted message" {
    const allocator = std.testing.allocator;
    const encrypt_mod = @import("encrypt.zig");
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();
    const receiver_pks = [_]key_mod.BoxPublicKey{receiver_kp.public_key};
    const ct = try encrypt_mod.seal(allocator, "hello", sender_kp.secret_key, &receiver_pks, .{});
    defer allocator.free(ct);
    try std.testing.expectError(sp_errors.Error.WrongMessageType, verify(allocator, ct));
}

test "verify V1 tampered payload fails" {
    const allocator = std.testing.allocator;
    const kp = key_mod.SigningKeyPair.generate();
    const msg = "v1 tamper test payload";

    const signed = try sign_mod.sign(allocator, msg, kp.secret_key, .{ .version = types.Version.v1() });
    defer signed.deinit();

    // Tamper with a byte near the middle of the signed message (in the payload area).
    const tampered = try allocator.alloc(u8, signed.data.len);
    defer allocator.free(tampered);
    @memcpy(tampered, signed.data);
    const tamper_idx = tampered.len / 2;
    tampered[tamper_idx] ^= 0xFF;

    const result = verify(allocator, tampered);
    try std.testing.expect(std.meta.isError(result));
}

test "sign and verify multi-block message larger than signature_block_size" {
    const allocator = std.testing.allocator;
    const kp = key_mod.SigningKeyPair.generate();

    // Create a message larger than signature_block_size (1 MiB) to force multiple blocks.
    const msg_len = types.signature_block_size + 1024;
    const msg = try allocator.alloc(u8, msg_len);
    defer allocator.free(msg);
    @memset(msg, 0x7A);

    const signed = try sign_mod.sign(allocator, msg, kp.secret_key, .{ .version = types.Version.v2() });
    defer signed.deinit();

    const result = try verify(allocator, signed.data);
    defer result.deinit();

    try std.testing.expect(result.signer.eql(kp.public_key));
    try std.testing.expectEqual(msg_len, result.plaintext.len);
    try std.testing.expectEqualSlices(u8, msg, result.plaintext);
}

// ---------------------------------------------------------------------------
// M22 - Trusted signers tests
// ---------------------------------------------------------------------------

test "verifyWithOptions attached accepts trusted signer" {
    const allocator = std.testing.allocator;
    const kp = key_mod.SigningKeyPair.generate();
    const msg = "trusted signer test";

    const signed = try sign_mod.sign(allocator, msg, kp.secret_key, .{ .version = types.Version.v2() });
    defer signed.deinit();

    const trusted = [_]key_mod.SigningPublicKey{kp.public_key};
    const result = try verifyWithOptions(allocator, signed.data, .{
        .trusted_signers = &trusted,
    });
    defer result.deinit();

    try std.testing.expect(result.signer.eql(kp.public_key));
    try std.testing.expectEqualSlices(u8, msg, result.plaintext);
}

test "verifyWithOptions attached rejects untrusted signer" {
    const allocator = std.testing.allocator;
    const kp_signer = key_mod.SigningKeyPair.generate();
    const kp_other = key_mod.SigningKeyPair.generate();
    const msg = "untrusted signer test";

    const signed = try sign_mod.sign(allocator, msg, kp_signer.secret_key, .{ .version = types.Version.v2() });
    defer signed.deinit();

    // Only trust kp_other, not kp_signer.
    const trusted = [_]key_mod.SigningPublicKey{kp_other.public_key};
    const result = verifyWithOptions(allocator, signed.data, .{
        .trusted_signers = &trusted,
    });
    try std.testing.expectError(sp_errors.Error.UntrustedSigner, result);
}

test "verifyWithOptions attached null trusted_signers accepts any" {
    const allocator = std.testing.allocator;
    const kp = key_mod.SigningKeyPair.generate();
    const msg = "null trusted signers test";

    const signed = try sign_mod.sign(allocator, msg, kp.secret_key, .{ .version = types.Version.v2() });
    defer signed.deinit();

    // null trusted_signers means accept any signer.
    const result = try verifyWithOptions(allocator, signed.data, .{
        .trusted_signers = null,
    });
    defer result.deinit();

    try std.testing.expect(result.signer.eql(kp.public_key));
}

test "verifyDetachedWithOptions accepts trusted signer" {
    const allocator = std.testing.allocator;
    const kp = key_mod.SigningKeyPair.generate();
    const msg = "detached trusted signer test";

    const sig_result = try sign_mod.signDetached(allocator, msg, kp.secret_key, .{ .version = types.Version.v2() });
    defer sig_result.deinit();

    const trusted = [_]key_mod.SigningPublicKey{kp.public_key};
    const result = try verifyDetachedWithOptions(allocator, msg, sig_result.data, .{
        .trusted_signers = &trusted,
    });

    try std.testing.expect(result.signer.eql(kp.public_key));
}

test "verifyDetachedWithOptions rejects untrusted signer" {
    const allocator = std.testing.allocator;
    const kp_signer = key_mod.SigningKeyPair.generate();
    const kp_other = key_mod.SigningKeyPair.generate();
    const msg = "detached untrusted signer test";

    const sig_result = try sign_mod.signDetached(allocator, msg, kp_signer.secret_key, .{ .version = types.Version.v2() });
    defer sig_result.deinit();

    const trusted = [_]key_mod.SigningPublicKey{kp_other.public_key};
    const result = verifyDetachedWithOptions(allocator, msg, sig_result.data, .{
        .trusted_signers = &trusted,
    });
    try std.testing.expectError(sp_errors.Error.UntrustedSigner, result);
}

test "verifyWithOptions trusted signers with multiple keys" {
    const allocator = std.testing.allocator;
    const kp1 = key_mod.SigningKeyPair.generate();
    const kp2 = key_mod.SigningKeyPair.generate();
    const kp3 = key_mod.SigningKeyPair.generate();
    const msg = "multi-key trust test";

    // Sign with kp2.
    const signed = try sign_mod.sign(allocator, msg, kp2.secret_key, .{ .version = types.Version.v2() });
    defer signed.deinit();

    // Trust kp1, kp2, kp3. kp2 is in the set, so it should pass.
    const trusted = [_]key_mod.SigningPublicKey{ kp1.public_key, kp2.public_key, kp3.public_key };
    const result = try verifyWithOptions(allocator, signed.data, .{
        .trusted_signers = &trusted,
    });
    defer result.deinit();

    try std.testing.expect(result.signer.eql(kp2.public_key));
}

// ---------------------------------------------------------------------------
// M23 - Version policy tests
// ---------------------------------------------------------------------------

test "verifyWithOptions v2Only accepts V2 message" {
    const allocator = std.testing.allocator;
    const kp = key_mod.SigningKeyPair.generate();
    const msg = "v2 only accept test";

    const signed = try sign_mod.sign(allocator, msg, kp.secret_key, .{ .version = types.Version.v2() });
    defer signed.deinit();

    const result = try verifyWithOptions(allocator, signed.data, .{
        .version_policy = types.VersionPolicy.v2Only(),
    });
    defer result.deinit();

    try std.testing.expectEqualSlices(u8, msg, result.plaintext);
}

test "verifyWithOptions v2Only rejects V1 message" {
    const allocator = std.testing.allocator;
    const kp = key_mod.SigningKeyPair.generate();
    const msg = "v2 only reject v1 test";

    const signed = try sign_mod.sign(allocator, msg, kp.secret_key, .{ .version = types.Version.v1() });
    defer signed.deinit();

    const result = verifyWithOptions(allocator, signed.data, .{
        .version_policy = types.VersionPolicy.v2Only(),
    });
    try std.testing.expectError(sp_errors.Error.VersionNotAllowed, result);
}

test "verifyWithOptions v1Only accepts V1 message" {
    const allocator = std.testing.allocator;
    const kp = key_mod.SigningKeyPair.generate();
    const msg = "v1 only accept test";

    const signed = try sign_mod.sign(allocator, msg, kp.secret_key, .{ .version = types.Version.v1() });
    defer signed.deinit();

    const result = try verifyWithOptions(allocator, signed.data, .{
        .version_policy = types.VersionPolicy.v1Only(),
    });
    defer result.deinit();

    try std.testing.expectEqualSlices(u8, msg, result.plaintext);
}

test "verifyWithOptions v1Only rejects V2 message" {
    const allocator = std.testing.allocator;
    const kp = key_mod.SigningKeyPair.generate();
    const msg = "v1 only reject v2 test";

    const signed = try sign_mod.sign(allocator, msg, kp.secret_key, .{ .version = types.Version.v2() });
    defer signed.deinit();

    const result = verifyWithOptions(allocator, signed.data, .{
        .version_policy = types.VersionPolicy.v1Only(),
    });
    try std.testing.expectError(sp_errors.Error.VersionNotAllowed, result);
}

test "verifyWithOptions v1OrV2 accepts both versions" {
    const allocator = std.testing.allocator;
    const kp = key_mod.SigningKeyPair.generate();
    const msg = "v1 or v2 test";

    // V1 message.
    const signed_v1 = try sign_mod.sign(allocator, msg, kp.secret_key, .{ .version = types.Version.v1() });
    defer signed_v1.deinit();
    const r1 = try verifyWithOptions(allocator, signed_v1.data, .{
        .version_policy = types.VersionPolicy.v1OrV2(),
    });
    defer r1.deinit();
    try std.testing.expectEqualSlices(u8, msg, r1.plaintext);

    // V2 message.
    const signed_v2 = try sign_mod.sign(allocator, msg, kp.secret_key, .{ .version = types.Version.v2() });
    defer signed_v2.deinit();
    const r2 = try verifyWithOptions(allocator, signed_v2.data, .{
        .version_policy = types.VersionPolicy.v1OrV2(),
    });
    defer r2.deinit();
    try std.testing.expectEqualSlices(u8, msg, r2.plaintext);
}

test "verifyWithOptions null version_policy accepts any version" {
    const allocator = std.testing.allocator;
    const kp = key_mod.SigningKeyPair.generate();
    const msg = "null version policy test";

    const signed = try sign_mod.sign(allocator, msg, kp.secret_key, .{ .version = types.Version.v1() });
    defer signed.deinit();

    const result = try verifyWithOptions(allocator, signed.data, .{
        .version_policy = null,
    });
    defer result.deinit();

    try std.testing.expectEqualSlices(u8, msg, result.plaintext);
}

test "verifyDetachedWithOptions v2Only accepts V2 detached" {
    const allocator = std.testing.allocator;
    const kp = key_mod.SigningKeyPair.generate();
    const msg = "detached v2 only test";

    const sig_result = try sign_mod.signDetached(allocator, msg, kp.secret_key, .{ .version = types.Version.v2() });
    defer sig_result.deinit();

    const result = try verifyDetachedWithOptions(allocator, msg, sig_result.data, .{
        .version_policy = types.VersionPolicy.v2Only(),
    });
    try std.testing.expect(result.signer.eql(kp.public_key));
}

test "verifyDetachedWithOptions v2Only rejects V1 detached" {
    const allocator = std.testing.allocator;
    const kp = key_mod.SigningKeyPair.generate();
    const msg = "detached v2 only reject v1 test";

    const sig_result = try sign_mod.signDetached(allocator, msg, kp.secret_key, .{ .version = types.Version.v1() });
    defer sig_result.deinit();

    const result = verifyDetachedWithOptions(allocator, msg, sig_result.data, .{
        .version_policy = types.VersionPolicy.v2Only(),
    });
    try std.testing.expectError(sp_errors.Error.VersionNotAllowed, result);
}

test "verifyWithOptions combined trusted signer and version policy" {
    const allocator = std.testing.allocator;
    const kp_trusted = key_mod.SigningKeyPair.generate();
    const kp_untrusted = key_mod.SigningKeyPair.generate();
    const msg = "combined test";

    // Sign with trusted key using V2.
    const signed = try sign_mod.sign(allocator, msg, kp_trusted.secret_key, .{ .version = types.Version.v2() });
    defer signed.deinit();

    const trusted = [_]key_mod.SigningPublicKey{kp_trusted.public_key};

    // Both constraints satisfied: trusted signer + V2 allowed.
    const result = try verifyWithOptions(allocator, signed.data, .{
        .trusted_signers = &trusted,
        .version_policy = types.VersionPolicy.v2Only(),
    });
    defer result.deinit();
    try std.testing.expectEqualSlices(u8, msg, result.plaintext);

    // Wrong version policy: V1 only, but message is V2.
    const result2 = verifyWithOptions(allocator, signed.data, .{
        .trusted_signers = &trusted,
        .version_policy = types.VersionPolicy.v1Only(),
    });
    try std.testing.expectError(sp_errors.Error.VersionNotAllowed, result2);

    // Wrong signer: message signed by kp_trusted but only kp_untrusted is trusted.
    const untrusted = [_]key_mod.SigningPublicKey{kp_untrusted.public_key};
    const result3 = verifyWithOptions(allocator, signed.data, .{
        .trusted_signers = &untrusted,
        .version_policy = types.VersionPolicy.v2Only(),
    });
    try std.testing.expectError(sp_errors.Error.UntrustedSigner, result3);
}

// ---------------------------------------------------------------------------
// Trailing garbage tests
// ---------------------------------------------------------------------------

test "verify V2 rejects trailing garbage after signed message" {
    const allocator = std.testing.allocator;
    const kp = key_mod.SigningKeyPair.generate();
    const msg = "trailing garbage v2 test";

    const signed = try sign_mod.sign(allocator, msg, kp.secret_key, .{ .version = types.Version.v2() });
    defer signed.deinit();

    // Append valid msgpack data (0xC3 = true) so the trailing read succeeds
    // and the verifier detects unexpected trailing data.
    const garbage = [_]u8{0xC3};
    const tampered = try allocator.alloc(u8, signed.data.len + garbage.len);
    defer allocator.free(tampered);
    @memcpy(tampered[0..signed.data.len], signed.data);
    @memcpy(tampered[signed.data.len..], &garbage);

    try std.testing.expectError(sp_errors.Error.TrailingGarbage, verify(allocator, tampered));
}

test "verify V1 rejects trailing garbage after signed message" {
    const allocator = std.testing.allocator;
    const kp = key_mod.SigningKeyPair.generate();
    const msg = "trailing garbage v1 test";

    const signed = try sign_mod.sign(allocator, msg, kp.secret_key, .{ .version = types.Version.v1() });
    defer signed.deinit();

    // Append valid msgpack data (0xC3 = true) so the trailing read succeeds
    // and the verifier detects unexpected trailing data.
    const garbage = [_]u8{0xC3};
    const tampered = try allocator.alloc(u8, signed.data.len + garbage.len);
    defer allocator.free(tampered);
    @memcpy(tampered[0..signed.data.len], signed.data);
    @memcpy(tampered[signed.data.len..], &garbage);

    try std.testing.expectError(sp_errors.Error.TrailingGarbage, verify(allocator, tampered));
}

// ---------------------------------------------------------------------------
// Empty input tests
// ---------------------------------------------------------------------------

test "verify empty input returns error" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(sp_errors.Error.FailedToReadHeaderBytes, verify(allocator, ""));
}

test "verifyDetached empty signature returns error" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(sp_errors.Error.FailedToReadHeaderBytes, verifyDetached(allocator, "", ""));
}

test "verifyDetached empty signature with non-empty message returns error" {
    const allocator = std.testing.allocator;
    try std.testing.expectError(sp_errors.Error.FailedToReadHeaderBytes, verifyDetached(allocator, "hello", ""));
}
