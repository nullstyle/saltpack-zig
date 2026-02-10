//! Streaming APIs for saltpack encrypt/decrypt, sign/verify operations.
//!
//! These types provide streaming wrappers around the existing saltpack operations,
//! allowing data to be processed incrementally rather than requiring everything in
//! memory at once. Each stream type buffers input until a full block is accumulated,
//! then processes it.
//!
//! ## Architecture
//!
//! - `EncryptStream` is a Writer that encrypts plaintext block-by-block and writes
//!   ciphertext to an underlying writer. Call `finish()` to flush the final block.
//! - `DecryptStream` is a Reader that reads ciphertext from an underlying reader
//!   and decrypts block-by-block, yielding plaintext.
//! - `SignStream` is a Writer that creates attached signatures in streaming fashion.
//!   Call `finish()` to write the final block.
//! - `VerifyStream` is a Reader that verifies attached signatures and extracts
//!   plaintext from signed messages.
//!
//! Each stream type handles header encoding/decoding internally on first use.

const std = @import("std");
const Allocator = std.mem.Allocator;

const types = @import("types.zig");
const sp_errors = @import("errors.zig");
const key_mod = @import("key.zig");
const nonce_mod = @import("nonce.zig");
const header_mod = @import("header.zig");
const encrypt_mod = @import("encrypt.zig");
const decrypt_mod = @import("decrypt.zig");
const sign_mod = @import("sign.zig");
const verify_mod = @import("verify.zig");

const SecretBox = std.crypto.nacl.SecretBox;
const NaclBox = std.crypto.nacl.Box;
const secureZero = std.crypto.secureZero;

const mp_utils = @import("msgpack_utils.zig");
const BufferStream = mp_utils.BufferStream;
const fixedBufferStream = mp_utils.fixedBufferStream;
const Payload = mp_utils.Payload;
const MsgPack = mp_utils.MsgPack;

const secretbox_tag_length = SecretBox.tag_length;

// ===========================================================================
// EncryptStream
// ===========================================================================

/// A streaming encryption writer that encrypts plaintext block-by-block and
/// writes the resulting ciphertext to an underlying writer.
///
/// Usage:
///   var stream = try EncryptStream(MyWriter).init(allocator, my_writer, sender, receivers, .{});
///   defer stream.deinit();
///   _ = try stream.write("hello world");
///   try stream.finish();
pub fn EncryptStream(comptime WriterType: type) type {
    return struct {
        const Self = @This();

        allocator: Allocator,
        underlying_writer: WriterType,

        // Encryption state
        version: types.Version,
        header_hash: types.HeaderHash,
        payload_key: types.PayloadKey,
        mac_keys: []types.MacKey,
        block_number: u64,
        num_receivers: usize,

        // Plaintext buffer (accumulates until block_size)
        buffer: []u8,
        buffer_len: usize,

        // Byte limit tracking
        bytes_processed: u64,
        max_bytes: ?u64,

        // State tracking
        finished: bool,

        pub const Error = WriterType.Error || Allocator.Error || sp_errors.Error ||
            error{ BadSignature, BadBoxKey, StreamAlreadyFinished, MaxMessageSizeExceeded };

        pub const GenWriter = std.io.GenericWriter(*Self, Error, genWrite);

        /// Initialize an EncryptStream. Encodes and writes the header immediately.
        pub fn init(
            allocator: Allocator,
            underlying_writer: WriterType,
            sender: ?key_mod.BoxSecretKey,
            receivers: []const key_mod.BoxPublicKey,
            opts: encrypt_mod.SealOptions,
        ) !Self {
            if (receivers.len == 0) return sp_errors.Error.BadReceivers;
            if (receivers.len > types.max_receiver_count) return sp_errors.Error.BadReceivers;

            // Check for duplicate receiver keys.
            for (receivers, 0..) |r1, i| {
                for (receivers[i + 1 ..]) |r2| {
                    if (std.crypto.timing_safe.eql([32]u8, r1.bytes, r2.bytes)) {
                        return sp_errors.Error.RepeatedKey;
                    }
                }
            }

            // Generate ephemeral key pair.
            var ephemeral_kp = key_mod.BoxKeyPair.generate();
            defer secureZero(u8, &ephemeral_kp.secret_key.bytes);

            // Determine the effective sender key.
            var effective_sender: key_mod.BoxSecretKey = sender orelse ephemeral_kp.secret_key;
            defer secureZero(u8, &effective_sender.bytes);

            // Generate random payload key.
            var payload_key: types.PayloadKey = undefined;
            std.crypto.random.bytes(&payload_key);
            errdefer secureZero(u8, &payload_key);

            // Encrypt sender public key with payload key.
            const sender_key_nonce = nonce_mod.senderKeyNonce();
            var sender_secretbox: [32 + secretbox_tag_length]u8 = undefined;
            SecretBox.seal(&sender_secretbox, &effective_sender.getPublicKey().bytes, sender_key_nonce, payload_key);

            // Build shuffled index mapping.
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

            // Build per-receiver payload key boxes.
            const pkb_len = 32 + secretbox_tag_length;
            const receiver_keys = try allocator.alloc(header_mod.ReceiverKeys, receivers.len);
            defer allocator.free(receiver_keys);
            const pkb_storage = try allocator.alloc(u8, receivers.len * pkb_len);
            defer allocator.free(pkb_storage);

            for (indices, 0..) |orig_idx, i| {
                const recv_pk = receivers[orig_idx];
                const recv_nonce = try nonce_mod.payloadKeyBoxNonce(opts.version, i);
                var shared_key = NaclBox.createSharedSecret(recv_pk.bytes, ephemeral_kp.secret_key.bytes) catch {
                    return sp_errors.Error.BadEphemeralKey;
                };
                defer secureZero(u8, &shared_key);

                const pkb_slice = pkb_storage[i * pkb_len .. (i + 1) * pkb_len];
                SecretBox.seal(pkb_slice, &payload_key, recv_nonce, shared_key);

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

            // Build shuffled receivers for MAC key computation.
            const shuffled_receivers = try allocator.alloc(key_mod.BoxPublicKey, receivers.len);
            defer allocator.free(shuffled_receivers);
            for (indices, 0..) |orig_idx, i| shuffled_receivers[i] = receivers[orig_idx];

            // Compute MAC keys.
            const mac_keys = try computeMacKeysSender(
                allocator,
                opts.version,
                effective_sender,
                ephemeral_kp.secret_key,
                shuffled_receivers,
                header_hash,
            );
            errdefer {
                for (mac_keys) |*k| secureZero(u8, k);
                allocator.free(mac_keys);
            }

            // Allocate plaintext buffer.
            const buffer = try allocator.alloc(u8, types.encryption_block_size);
            errdefer allocator.free(buffer);

            // Write header to underlying writer.
            try writeAllGeneric(WriterType, underlying_writer, header_result.encoded);

            return Self{
                .allocator = allocator,
                .underlying_writer = underlying_writer,
                .version = opts.version,
                .header_hash = header_hash,
                .payload_key = payload_key,
                .mac_keys = mac_keys,
                .block_number = 0,
                .num_receivers = receivers.len,
                .buffer = buffer,
                .buffer_len = 0,
                .bytes_processed = 0,
                .max_bytes = null,
                .finished = false,
            };
        }

        /// Clean up all allocated resources.
        pub fn deinit(self: *Self) void {
            secureZero(u8, &self.payload_key);
            for (self.mac_keys) |*k| secureZero(u8, k);
            self.allocator.free(self.mac_keys);
            // Zero the buffer before freeing (may contain plaintext).
            secureZero(u8, self.buffer);
            self.allocator.free(self.buffer);
        }

        /// Set the maximum number of plaintext bytes that may be processed.
        /// Pass `null` for unlimited (the default).
        pub fn setMaxBytes(self: *Self, max: ?u64) void {
            self.max_bytes = max;
        }

        /// Returns a GenericWriter interface for this stream.
        pub fn writer(self: *Self) GenWriter {
            return .{ .context = self };
        }

        /// Write plaintext data into the stream. Full blocks are encrypted
        /// and written to the underlying writer immediately.
        pub fn write(self: *Self, data: []const u8) Error!usize {
            if (self.finished) return error.StreamAlreadyFinished;

            // Check byte limit before processing.
            if (self.max_bytes) |limit| {
                if (self.bytes_processed + data.len > limit) {
                    return error.MaxMessageSizeExceeded;
                }
            }
            self.bytes_processed += data.len;

            const block_size = types.encryption_block_size;
            var offset: usize = 0;

            while (offset < data.len) {
                const space = block_size - self.buffer_len;
                const to_copy = @min(space, data.len - offset);
                @memcpy(self.buffer[self.buffer_len .. self.buffer_len + to_copy], data[offset .. offset + to_copy]);
                self.buffer_len += to_copy;
                offset += to_copy;

                // If buffer is full, flush this block (not final).
                if (self.buffer_len == block_size) {
                    try self.flushBlock();
                }
            }

            return data.len;
        }

        /// GenericWriter-compatible write function.
        fn genWrite(self: *Self, data: []const u8) Error!usize {
            return self.write(data);
        }

        /// Finish the stream by writing the final block.
        /// Must be called exactly once after all data has been written.
        pub fn finish(self: *Self) Error!void {
            if (self.finished) return error.StreamAlreadyFinished;
            self.finished = true;

            switch (self.version.major) {
                1 => {
                    // V1: If we have buffered data, write it as a non-final block,
                    // then write an empty final block.
                    if (self.buffer_len > 0) {
                        try self.flushBlock();
                    }
                    // Empty final block.
                    if (self.block_number > types.max_block_number) return sp_errors.Error.PacketOverflow;
                    try self.encryptAndWriteBlock(&[_]u8{}, true);
                    self.block_number += 1;
                },
                2 => {
                    // V2: Write the remaining data as the final block.
                    if (self.block_number > types.max_block_number) return sp_errors.Error.PacketOverflow;
                    try self.encryptAndWriteBlock(self.buffer[0..self.buffer_len], true);
                    self.buffer_len = 0;
                    self.block_number += 1;
                },
                else => return sp_errors.Error.BadVersion,
            }
        }

        fn flushBlock(self: *Self) Error!void {
            if (self.block_number > types.max_block_number) return sp_errors.Error.PacketOverflow;

            try self.encryptAndWriteBlock(self.buffer[0..self.buffer_len], false);
            self.buffer_len = 0;
            self.block_number += 1;
        }

        fn encryptAndWriteBlock(self: *Self, chunk: []const u8, is_final: bool) Error!void {
            // Encrypt the chunk.
            const block_nonce = nonce_mod.payloadNonce(self.block_number);
            const ct_len = chunk.len + secretbox_tag_length;
            const ciphertext = try self.allocator.alloc(u8, ct_len);
            defer self.allocator.free(ciphertext);
            SecretBox.seal(ciphertext, chunk, block_nonce, self.payload_key);

            // Compute payload hash.
            const payload_hash = encrypt_mod.computePayloadHash(self.version, self.header_hash, block_nonce, ciphertext, is_final);

            // Compute per-receiver authenticators.
            const authenticators = try self.allocator.alloc(types.PayloadAuthenticator, self.mac_keys.len);
            defer self.allocator.free(authenticators);
            for (self.mac_keys, 0..) |mk, i| {
                authenticators[i] = encrypt_mod.computePayloadAuthenticator(mk, payload_hash);
            }

            // Encode and write the block.
            const encoded = encodeEncryptionBlock(self.allocator, self.version, authenticators, ciphertext, is_final) catch {
                return sp_errors.Error.BadCiphertext;
            };
            defer self.allocator.free(encoded);
            try writeAllGeneric(WriterType, self.underlying_writer, encoded);
        }
    };
}

/// Create an EncryptStream for a given writer type.
pub fn encryptStream(
    allocator: Allocator,
    underlying_writer: anytype,
    sender: ?key_mod.BoxSecretKey,
    receivers: []const key_mod.BoxPublicKey,
    opts: encrypt_mod.SealOptions,
) !EncryptStream(@TypeOf(underlying_writer)) {
    return EncryptStream(@TypeOf(underlying_writer)).init(allocator, underlying_writer, sender, receivers, opts);
}

// ===========================================================================
// DecryptStream
// ===========================================================================

/// A streaming decryption reader that reads ciphertext from an underlying reader
/// and decrypts block-by-block, yielding plaintext.
///
/// Usage:
///   var stream = try DecryptStream(MyReader).init(allocator, my_reader, keyring);
///   defer stream.deinit();
///   const data = try stream.readAllAlloc(allocator, max_size);
pub fn DecryptStream(comptime ReaderType: type) type {
    return struct {
        const Self = @This();

        allocator: Allocator,
        underlying_reader: ReaderType,

        // Decryption state
        version: types.Version,
        header_hash: types.HeaderHash,
        payload_key: types.PayloadKey,
        mac_key: types.MacKey,
        receiver_index: usize,
        num_receivers: usize,
        block_number: u64,

        // Key info for caller inspection
        key_info: sp_errors.MessageKeyInfo,

        // Output buffer (decrypted plaintext from current block)
        out_buffer: []u8,
        out_pos: usize,
        out_len: usize,

        // Raw ciphertext buffer for reading from underlying reader
        raw_buffer: []u8,
        raw_len: usize,

        // Byte limit tracking
        bytes_processed: u64,
        max_bytes: ?u64,

        // State tracking
        saw_final: bool,

        pub const Error = ReaderType.Error || Allocator.Error || sp_errors.Error ||
            error{ BadSignature, BadBoxKey, EndOfStream, MaxMessageSizeExceeded };

        pub const GenReader = std.io.GenericReader(*Self, Error, genRead);

        /// Initialize a DecryptStream. Reads and decodes the header from the reader.
        pub fn init(
            allocator: Allocator,
            underlying_reader: ReaderType,
            keyring: []const key_mod.BoxKeyPair,
        ) !Self {
            // Read header from the stream.
            // A valid header with max_receiver_count (2048) receivers can be ~525KB,
            // so we compute a generous upper bound to avoid rejecting valid messages.
            const max_header_size: usize = 1024 + types.max_receiver_count * 256;
            const header_buf = try allocator.alloc(u8, max_header_size);
            defer allocator.free(header_buf);

            var total_read: usize = 0;
            while (total_read < max_header_size) {
                const n = underlying_reader.read(header_buf[total_read..]) catch |err| {
                    if (total_read == 0) return sp_errors.Error.FailedToReadHeaderBytes;
                    return err;
                };
                if (n == 0) break;
                total_read += n;
            }

            if (total_read == 0) return sp_errors.Error.FailedToReadHeaderBytes;

            // Determine the header size by parsing the outer msgpack element.
            const header_bytes_len = try measureMsgpackElement(allocator, header_buf[0..total_read]);

            // Decode the header.
            const decoded = header_mod.decodeHeader(allocator, header_buf[0..header_bytes_len]) catch {
                return sp_errors.Error.FailedToReadHeaderBytes;
            };

            const enc_header = switch (decoded) {
                .encryption => |enc| enc,
                .signature => return sp_errors.Error.WrongMessageType,
            };

            if (enc_header.header.message_type != .encryption) {
                allocator.free(enc_header.header.sender_secretbox);
                header_mod.freeDecodedReceivers(allocator, enc_header.header.receivers);
                return sp_errors.Error.WrongMessageType;
            }

            const version = enc_header.header.version;
            const header_hash = enc_header.hash;
            const ephemeral_pk = key_mod.BoxPublicKey.fromBytes(enc_header.header.ephemeral_key) catch {
                allocator.free(enc_header.header.sender_secretbox);
                header_mod.freeDecodedReceivers(allocator, enc_header.header.receivers);
                return sp_errors.Error.BadEphemeralKey;
            };

            // Try to recover the payload key.
            const recovery = try recoverPayloadKey(enc_header.header, keyring) orelse {
                allocator.free(enc_header.header.sender_secretbox);
                header_mod.freeDecodedReceivers(allocator, enc_header.header.receivers);
                return sp_errors.Error.NoDecryptionKey;
            };

            var payload_key = recovery.payload_key;
            const receiver_key = recovery.receiver_key;
            const receiver_index = recovery.receiver_index;

            // Decrypt sender public key.
            const sender_key_nonce = nonce_mod.senderKeyNonce();
            var sender_pk_bytes: [32]u8 = undefined;
            SecretBox.open(&sender_pk_bytes, enc_header.header.sender_secretbox, sender_key_nonce, payload_key) catch {
                secureZero(u8, &payload_key);
                allocator.free(enc_header.header.sender_secretbox);
                header_mod.freeDecodedReceivers(allocator, enc_header.header.receivers);
                return sp_errors.Error.DecryptionFailed;
            };

            const sender_is_anon = std.crypto.timing_safe.eql([32]u8, sender_pk_bytes, enc_header.header.ephemeral_key);
            const sender_pk = key_mod.BoxPublicKey.fromBytes(sender_pk_bytes) catch {
                return sp_errors.Error.DecryptionFailed;
            };

            // Compute MAC key.
            const mac_key = try encrypt_mod.computeMacKeyReceiver(
                version,
                receiver_key,
                sender_pk,
                ephemeral_pk,
                header_hash,
                receiver_index,
            );

            const num_receivers = enc_header.header.receivers.len;

            // Build key info.
            var key_info = sp_errors.MessageKeyInfo{
                .num_recipients = num_receivers,
                .receiver_key_index = receiver_index,
            };
            if (sender_is_anon) {
                key_info.sender_is_anonymous = true;
            } else {
                key_info.sender_key = sender_pk_bytes;
            }

            // Free header allocations.
            allocator.free(enc_header.header.sender_secretbox);
            header_mod.freeDecodedReceivers(allocator, enc_header.header.receivers);

            secureZero(u8, &sender_pk_bytes);

            // Allocate output buffer.
            const out_buffer = try allocator.alloc(u8, types.encryption_block_size);
            errdefer allocator.free(out_buffer);

            // Copy leftover bytes (data after header) into raw buffer.
            const leftover_len = total_read - header_bytes_len;
            const raw_buffer = try allocator.alloc(u8, types.encryption_block_size * 2 + 4096);
            if (leftover_len > 0) {
                @memcpy(raw_buffer[0..leftover_len], header_buf[header_bytes_len..total_read]);
            }

            return Self{
                .allocator = allocator,
                .underlying_reader = underlying_reader,
                .version = version,
                .header_hash = header_hash,
                .payload_key = payload_key,
                .mac_key = mac_key,
                .receiver_index = receiver_index,
                .num_receivers = num_receivers,
                .block_number = 0,
                .key_info = key_info,
                .out_buffer = out_buffer,
                .out_pos = 0,
                .out_len = 0,
                .raw_buffer = raw_buffer,
                .raw_len = leftover_len,
                .bytes_processed = 0,
                .max_bytes = null,
                .saw_final = false,
            };
        }

        pub fn deinit(self: *Self) void {
            secureZero(u8, &self.payload_key);
            secureZero(u8, &self.mac_key);
            // Zero out_buffer before freeing (contains decrypted plaintext).
            secureZero(u8, self.out_buffer);
            self.allocator.free(self.out_buffer);
            secureZero(u8, self.raw_buffer);
            self.allocator.free(self.raw_buffer);
        }

        /// Set the maximum number of plaintext bytes that may be read.
        /// Pass `null` for unlimited (the default).
        pub fn setMaxBytes(self: *Self, max: ?u64) void {
            self.max_bytes = max;
        }

        /// Returns a GenericReader interface for this stream.
        pub fn reader(self: *Self) GenReader {
            return .{ .context = self };
        }

        /// Read decrypted plaintext into the destination buffer.
        pub fn read(self: *Self, dest: []u8) Error!usize {
            return self.genRead(dest);
        }

        /// GenericReader-compatible read function.
        fn genRead(self: *Self, dest: []u8) Error!usize {
            // Serve from output buffer first.
            if (self.out_pos < self.out_len) {
                const available = self.out_len - self.out_pos;
                const to_copy = @min(available, dest.len);
                // Check byte limit before returning data.
                if (self.max_bytes) |limit| {
                    if (self.bytes_processed + to_copy > limit) {
                        return error.MaxMessageSizeExceeded;
                    }
                }
                @memcpy(dest[0..to_copy], self.out_buffer[self.out_pos .. self.out_pos + to_copy]);
                self.out_pos += to_copy;
                self.bytes_processed += to_copy;
                return to_copy;
            }

            if (self.saw_final) return 0;

            try self.decodeNextBlock();

            if (self.out_pos < self.out_len) {
                const available = self.out_len - self.out_pos;
                const to_copy = @min(available, dest.len);
                // Check byte limit before returning data.
                if (self.max_bytes) |limit| {
                    if (self.bytes_processed + to_copy > limit) {
                        return error.MaxMessageSizeExceeded;
                    }
                }
                @memcpy(dest[0..to_copy], self.out_buffer[self.out_pos .. self.out_pos + to_copy]);
                self.out_pos += to_copy;
                self.bytes_processed += to_copy;
                return to_copy;
            }

            return 0;
        }

        fn decodeNextBlock(self: *Self) Error!void {
            if (self.block_number > types.max_block_number) return sp_errors.Error.PacketOverflow;

            try self.fillRawBuffer();

            if (self.raw_len == 0) return sp_errors.Error.TruncatedMessage;

            const block_result = decodeEncryptionBlock(self.allocator, self.raw_buffer[0..self.raw_len], self.version, self.num_receivers) catch {
                if (self.block_number == 0) return sp_errors.Error.TruncatedMessage;
                return sp_errors.Error.BadCiphertext;
            };
            defer self.allocator.free(block_result.ciphertext);
            defer self.allocator.free(block_result.authenticators);

            // Remove consumed bytes from raw buffer.
            const remaining = self.raw_len - block_result.bytes_consumed;
            if (remaining > 0) {
                std.mem.copyForwards(u8, self.raw_buffer[0..remaining], self.raw_buffer[block_result.bytes_consumed..self.raw_len]);
            }
            self.raw_len = remaining;

            const ct = block_result.ciphertext;
            const is_final = block_result.is_final;

            // Verify authenticator.
            const block_nonce = nonce_mod.payloadNonce(self.block_number);
            const payload_hash = encrypt_mod.computePayloadHash(self.version, self.header_hash, block_nonce, ct, is_final);
            const expected_auth = encrypt_mod.computePayloadAuthenticator(self.mac_key, payload_hash);

            if (block_result.authenticators.len <= self.receiver_index) {
                return sp_errors.Error.DecryptionFailed;
            }
            if (!std.crypto.timing_safe.eql(
                types.PayloadAuthenticator,
                expected_auth,
                block_result.authenticators[self.receiver_index],
            )) {
                return sp_errors.Error.DecryptionFailed;
            }

            // Decrypt.
            if (ct.len < secretbox_tag_length) return sp_errors.Error.BadCiphertext;
            const pt_len = ct.len - secretbox_tag_length;

            SecretBox.open(self.out_buffer[0..pt_len], ct, block_nonce, self.payload_key) catch {
                return sp_errors.Error.BadCiphertext;
            };

            self.out_pos = 0;
            self.out_len = pt_len;
            self.block_number += 1;

            if (is_final) {
                self.saw_final = true;
            }
        }

        fn fillRawBuffer(self: *Self) Error!void {
            const space = self.raw_buffer.len - self.raw_len;
            if (space == 0) return;

            const n = self.underlying_reader.read(self.raw_buffer[self.raw_len..]) catch |err| {
                // If we have no buffered data, propagate the error immediately.
                if (self.raw_len == 0) return err;
                // Otherwise we have data to process; store the error for later.
                return;
            };
            self.raw_len += n;
        }
    };
}

/// Create a DecryptStream for a given reader type.
pub fn decryptStream(
    allocator: Allocator,
    underlying_reader: anytype,
    keyring: []const key_mod.BoxKeyPair,
) !DecryptStream(@TypeOf(underlying_reader)) {
    return DecryptStream(@TypeOf(underlying_reader)).init(allocator, underlying_reader, keyring);
}

// ===========================================================================
// SignStream
// ===========================================================================

/// A streaming signing writer that creates an attached signature message
/// block-by-block, writing signed data to an underlying writer.
pub fn SignStream(comptime WriterType: type) type {
    return struct {
        const Self = @This();

        allocator: Allocator,
        underlying_writer: WriterType,

        // Signing state
        version: types.Version,
        header_hash: types.HeaderHash,
        signer: key_mod.SigningSecretKey,
        seqno: u64,

        // Plaintext buffer
        buffer: []u8,
        buffer_len: usize,

        // Byte limit tracking
        bytes_processed: u64,
        max_bytes: ?u64,

        // State tracking
        finished: bool,

        pub const Error = WriterType.Error || Allocator.Error || sp_errors.Error ||
            error{ BadSignature, BadBoxKey, StreamAlreadyFinished, MaxMessageSizeExceeded };

        pub const GenWriter = std.io.GenericWriter(*Self, Error, genWrite);

        /// Initialize a SignStream. Encodes and writes the header immediately.
        pub fn init(
            allocator: Allocator,
            underlying_writer: WriterType,
            signer: key_mod.SigningSecretKey,
            opts: sign_mod.SignOptions,
        ) !Self {
            const sig_header = header_mod.SignatureHeader{
                .version = opts.version,
                .message_type = .attached_signature,
                .sender_public_key = signer.getPublicKey().bytes,
                .nonce = nonce_mod.generateSignatureNonce(),
            };

            const header_result = try header_mod.encodeSignatureHeader(allocator, sig_header);
            defer allocator.free(header_result.encoded);

            // Write header.
            try writeAllGeneric(WriterType, underlying_writer, header_result.encoded);

            // Allocate buffer.
            const buffer = try allocator.alloc(u8, types.signature_block_size);

            return Self{
                .allocator = allocator,
                .underlying_writer = underlying_writer,
                .version = opts.version,
                .header_hash = header_result.header_hash,
                .signer = signer,
                .seqno = 0,
                .buffer = buffer,
                .buffer_len = 0,
                .bytes_processed = 0,
                .max_bytes = null,
                .finished = false,
            };
        }

        pub fn deinit(self: *Self) void {
            secureZero(u8, &self.signer.bytes);
            // Zero the full buffer (previously flushed data may remain beyond buffer_len).
            secureZero(u8, self.buffer);
            self.allocator.free(self.buffer);
        }

        /// Set the maximum number of plaintext bytes that may be processed.
        /// Pass `null` for unlimited (the default).
        pub fn setMaxBytes(self: *Self, max: ?u64) void {
            self.max_bytes = max;
        }

        /// Returns a GenericWriter interface for this stream.
        pub fn writer(self: *Self) GenWriter {
            return .{ .context = self };
        }

        /// Write plaintext data into the stream.
        pub fn write(self: *Self, data: []const u8) Error!usize {
            if (self.finished) return error.StreamAlreadyFinished;

            // Check byte limit before processing.
            if (self.max_bytes) |limit| {
                if (self.bytes_processed + data.len > limit) {
                    return error.MaxMessageSizeExceeded;
                }
            }
            self.bytes_processed += data.len;

            const block_size = types.signature_block_size;
            var offset: usize = 0;

            while (offset < data.len) {
                const space = block_size - self.buffer_len;
                const to_copy = @min(space, data.len - offset);
                @memcpy(self.buffer[self.buffer_len .. self.buffer_len + to_copy], data[offset .. offset + to_copy]);
                self.buffer_len += to_copy;
                offset += to_copy;

                if (self.buffer_len == block_size) {
                    try self.flushBlock();
                }
            }

            return data.len;
        }

        /// GenericWriter-compatible write function.
        fn genWrite(self: *Self, data: []const u8) Error!usize {
            return self.write(data);
        }

        /// Finish the stream by writing the final block.
        pub fn finish(self: *Self) Error!void {
            if (self.finished) return error.StreamAlreadyFinished;
            self.finished = true;

            switch (self.version.major) {
                1 => {
                    if (self.buffer_len > 0) {
                        try self.flushBlock();
                    }
                    if (self.seqno > types.max_block_number) return sp_errors.Error.PacketOverflow;
                    try self.signAndWriteBlock(&[_]u8{}, true);
                    self.seqno += 1;
                },
                2 => {
                    if (self.seqno > types.max_block_number) return sp_errors.Error.PacketOverflow;
                    try self.signAndWriteBlock(self.buffer[0..self.buffer_len], true);
                    self.buffer_len = 0;
                    self.seqno += 1;
                },
                else => return sp_errors.Error.BadVersion,
            }
        }

        fn flushBlock(self: *Self) Error!void {
            if (self.seqno > types.max_block_number) return sp_errors.Error.PacketOverflow;

            try self.signAndWriteBlock(self.buffer[0..self.buffer_len], false);
            self.buffer_len = 0;
            self.seqno += 1;
        }

        fn signAndWriteBlock(self: *Self, chunk: []const u8, is_final: bool) Error!void {
            const sig_bytes = try computeAttachedSignature(self.signer, self.version, self.header_hash, chunk, self.seqno, is_final);

            const encoded = encodeSignatureBlock(self.allocator, self.version, &sig_bytes, chunk, is_final) catch {
                return sp_errors.Error.BadSignature;
            };
            defer self.allocator.free(encoded);
            try writeAllGeneric(WriterType, self.underlying_writer, encoded);
        }
    };
}

/// Create a SignStream for a given writer type.
pub fn signStream(
    allocator: Allocator,
    underlying_writer: anytype,
    signer: key_mod.SigningSecretKey,
    opts: sign_mod.SignOptions,
) !SignStream(@TypeOf(underlying_writer)) {
    return SignStream(@TypeOf(underlying_writer)).init(allocator, underlying_writer, signer, opts);
}

// ===========================================================================
// VerifyStream
// ===========================================================================

/// A streaming verification reader that reads a signed message from an underlying
/// reader, verifies signatures block-by-block, and yields plaintext.
pub fn VerifyStream(comptime ReaderType: type) type {
    return struct {
        const Self = @This();

        allocator: Allocator,
        underlying_reader: ReaderType,

        // Verification state
        version: types.Version,
        header_hash: types.HeaderHash,
        sender_pk: key_mod.SigningPublicKey,
        seqno: u64,

        // Output buffer
        out_buffer: []u8,
        out_pos: usize,
        out_len: usize,

        // Raw buffer for reading from underlying reader
        raw_buffer: []u8,
        raw_len: usize,

        // Byte limit tracking
        bytes_processed: u64,
        max_bytes: ?u64,

        // State tracking
        saw_final: bool,

        pub const Error = ReaderType.Error || Allocator.Error || sp_errors.Error ||
            error{ BadSignature, BadBoxKey, EndOfStream, MaxMessageSizeExceeded };

        pub const GenReader = std.io.GenericReader(*Self, Error, genRead);

        /// Initialize a VerifyStream. Reads and decodes the header from the reader.
        pub fn init(
            allocator: Allocator,
            underlying_reader: ReaderType,
        ) !Self {
            // A valid header with max_receiver_count (2048) receivers can be ~525KB,
            // so we compute a generous upper bound to avoid rejecting valid messages.
            const max_header_size: usize = 1024 + types.max_receiver_count * 256;
            const header_buf = try allocator.alloc(u8, max_header_size);
            defer allocator.free(header_buf);

            var total_read: usize = 0;
            while (total_read < max_header_size) {
                const n = underlying_reader.read(header_buf[total_read..]) catch |err| {
                    if (total_read == 0) return sp_errors.Error.FailedToReadHeaderBytes;
                    return err;
                };
                if (n == 0) break;
                total_read += n;
            }

            if (total_read == 0) return sp_errors.Error.FailedToReadHeaderBytes;

            const header_bytes_len = try measureMsgpackElement(allocator, header_buf[0..total_read]);

            const decoded = header_mod.decodeHeader(allocator, header_buf[0..header_bytes_len]) catch {
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

            if (sig_info.header.message_type != .attached_signature) {
                return sp_errors.Error.WrongMessageType;
            }

            const version = sig_info.header.version;
            const sender_pk = try key_mod.SigningPublicKey.fromBytes(sig_info.header.sender_public_key);
            const header_hash = sig_info.hash;

            const out_buffer = try allocator.alloc(u8, types.signature_block_size);
            errdefer allocator.free(out_buffer);

            const leftover_len = total_read - header_bytes_len;
            const raw_buffer = try allocator.alloc(u8, types.signature_block_size * 2 + 4096);
            if (leftover_len > 0) {
                @memcpy(raw_buffer[0..leftover_len], header_buf[header_bytes_len..total_read]);
            }

            return Self{
                .allocator = allocator,
                .underlying_reader = underlying_reader,
                .version = version,
                .header_hash = header_hash,
                .sender_pk = sender_pk,
                .seqno = 0,
                .out_buffer = out_buffer,
                .out_pos = 0,
                .out_len = 0,
                .raw_buffer = raw_buffer,
                .raw_len = leftover_len,
                .bytes_processed = 0,
                .max_bytes = null,
                .saw_final = false,
            };
        }

        pub fn deinit(self: *Self) void {
            secureZero(u8, self.out_buffer);
            self.allocator.free(self.out_buffer);
            secureZero(u8, self.raw_buffer);
            self.allocator.free(self.raw_buffer);
        }

        /// Set the maximum number of plaintext bytes that may be read.
        /// Pass `null` for unlimited (the default).
        pub fn setMaxBytes(self: *Self, max: ?u64) void {
            self.max_bytes = max;
        }

        /// Returns a GenericReader interface for this stream.
        pub fn reader(self: *Self) GenReader {
            return .{ .context = self };
        }

        /// Get the signer's public key (available after init).
        pub fn getSigner(self: *const Self) key_mod.SigningPublicKey {
            return self.sender_pk;
        }

        /// Read verified plaintext.
        pub fn read(self: *Self, dest: []u8) Error!usize {
            return self.genRead(dest);
        }

        /// GenericReader-compatible read function.
        fn genRead(self: *Self, dest: []u8) Error!usize {
            if (self.out_pos < self.out_len) {
                const available = self.out_len - self.out_pos;
                const to_copy = @min(available, dest.len);
                // Check byte limit before returning data.
                if (self.max_bytes) |limit| {
                    if (self.bytes_processed + to_copy > limit) {
                        return error.MaxMessageSizeExceeded;
                    }
                }
                @memcpy(dest[0..to_copy], self.out_buffer[self.out_pos .. self.out_pos + to_copy]);
                self.out_pos += to_copy;
                self.bytes_processed += to_copy;
                return to_copy;
            }

            if (self.saw_final) return 0;

            try self.verifyNextBlock();

            if (self.out_pos < self.out_len) {
                const available = self.out_len - self.out_pos;
                const to_copy = @min(available, dest.len);
                // Check byte limit before returning data.
                if (self.max_bytes) |limit| {
                    if (self.bytes_processed + to_copy > limit) {
                        return error.MaxMessageSizeExceeded;
                    }
                }
                @memcpy(dest[0..to_copy], self.out_buffer[self.out_pos .. self.out_pos + to_copy]);
                self.out_pos += to_copy;
                self.bytes_processed += to_copy;
                return to_copy;
            }

            return 0;
        }

        fn verifyNextBlock(self: *Self) Error!void {
            if (self.seqno > types.max_block_number) return sp_errors.Error.PacketOverflow;

            try self.fillRawBuffer();

            if (self.raw_len == 0) return sp_errors.Error.TruncatedMessage;

            const block = decodeSignatureBlockFromBuf(self.allocator, self.raw_buffer[0..self.raw_len], self.version) catch {
                return sp_errors.Error.TruncatedMessage;
            };
            defer self.allocator.free(block.signature);
            defer self.allocator.free(block.payload_chunk);

            const remaining = self.raw_len - block.bytes_consumed;
            if (remaining > 0) {
                std.mem.copyForwards(u8, self.raw_buffer[0..remaining], self.raw_buffer[block.bytes_consumed..self.raw_len]);
            }
            self.raw_len = remaining;

            if (block.signature.len != 64) return sp_errors.Error.BadSignature;
            var sig_bytes: [64]u8 = undefined;
            @memcpy(&sig_bytes, block.signature);

            const sig_input = sign_mod.computeAttachedSignatureInput(
                self.version,
                self.header_hash,
                block.payload_chunk,
                self.seqno,
                block.is_final,
            );

            self.sender_pk.verify(&sig_input, sig_bytes) catch {
                return sp_errors.Error.BadSignature;
            };

            if (self.version.major == 2) {
                if (block.payload_chunk.len == 0 and (self.seqno != 0 or !block.is_final)) {
                    return sp_errors.Error.UnexpectedEmptyBlock;
                }
            }

            if (block.payload_chunk.len > 0) {
                @memcpy(self.out_buffer[0..block.payload_chunk.len], block.payload_chunk);
            }
            self.out_pos = 0;
            self.out_len = block.payload_chunk.len;

            self.seqno += 1;

            if (block.is_final) {
                self.saw_final = true;
            }
        }

        fn fillRawBuffer(self: *Self) Error!void {
            const space = self.raw_buffer.len - self.raw_len;
            if (space == 0) return;

            const n = self.underlying_reader.read(self.raw_buffer[self.raw_len..]) catch |err| {
                // If we have no buffered data, propagate the error immediately.
                if (self.raw_len == 0) return err;
                // Otherwise we have data to process; store the error for later.
                return;
            };
            self.raw_len += n;
        }
    };
}

/// Create a VerifyStream for a given reader type.
pub fn verifyStream(
    allocator: Allocator,
    underlying_reader: anytype,
) !VerifyStream(@TypeOf(underlying_reader)) {
    return VerifyStream(@TypeOf(underlying_reader)).init(allocator, underlying_reader);
}

// ===========================================================================
// Generic writer helper
// ===========================================================================

/// Write all bytes to a generic writer that has a writeAll method.
fn writeAllGeneric(comptime WriterType: type, w: WriterType, data: []const u8) !void {
    // Try writeAll first (for GenericWriter types).
    if (@hasDecl(WriterType, "writeAll")) {
        return w.writeAll(data);
    } else {
        // Fallback: use write in a loop.
        var written: usize = 0;
        while (written < data.len) {
            written += try w.write(data[written..]);
        }
    }
}

// ===========================================================================
// Shared internal helpers
// ===========================================================================

/// Measure the size of the first msgpack element in data (bytes consumed).
fn measureMsgpackElement(allocator: Allocator, data: []const u8) !usize {
    const read_buf_storage = try allocator.alloc(u8, data.len);
    defer allocator.free(read_buf_storage);
    @memcpy(read_buf_storage, data);
    var read_buf = fixedBufferStream(read_buf_storage);

    var dummy_write_storage: [1]u8 = undefined;
    var dummy_write = fixedBufferStream(&dummy_write_storage);
    var packer = MsgPack.init(&dummy_write, &read_buf);

    const payload = packer.read(allocator) catch {
        return sp_errors.Error.FailedToReadHeaderBytes;
    };
    defer payload.free(allocator);

    return read_buf.pos;
}

// Imported from decrypt_mod (was duplicated here).
const recoverPayloadKey = decrypt_mod.recoverPayloadKey;

// Imported from encrypt_mod (was duplicated here).
const computeMacKeysSender = encrypt_mod.computeMacKeysSender;

/// Encode an encryption block to bytes.
fn encodeEncryptionBlock(
    allocator: Allocator,
    version: types.Version,
    authenticators: []const types.PayloadAuthenticator,
    ciphertext: []const u8,
    is_final: bool,
) ![]u8 {
    return switch (version.major) {
        1 => try encodeEncBlockV1(allocator, authenticators, ciphertext),
        2 => try encodeEncBlockV2(allocator, authenticators, ciphertext, is_final),
        else => sp_errors.Error.BadVersion,
    };
}

fn encodeEncBlockV1(
    allocator: Allocator,
    authenticators: []const types.PayloadAuthenticator,
    ciphertext: []const u8,
) ![]u8 {
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

    const data_len = authenticators.len * 32 + ciphertext.len;
    return try serializePayload(allocator, arr, data_len);
}

fn encodeEncBlockV2(
    allocator: Allocator,
    authenticators: []const types.PayloadAuthenticator,
    ciphertext: []const u8,
    is_final: bool,
) ![]u8 {
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

    const data_len = authenticators.len * 32 + ciphertext.len;
    return try serializePayload(allocator, arr, data_len);
}

// Imported from decrypt_mod (was duplicated here).
const BlockDecodeResult = decrypt_mod.BlockDecodeResult;
const decodeEncryptionBlock = decrypt_mod.decodeEncryptionBlock;

// Imported from sign_mod (was duplicated here).
const computeAttachedSignature = sign_mod.computeAttachedSignature;

/// Encode a signature block to bytes.
fn encodeSignatureBlock(
    allocator: Allocator,
    version: types.Version,
    signature: []const u8,
    payload_chunk: []const u8,
    is_final: bool,
) ![]u8 {
    return switch (version.major) {
        1 => try encodeSigBlockV1(allocator, signature, payload_chunk),
        2 => try encodeSigBlockV2(allocator, signature, payload_chunk, is_final),
        else => sp_errors.Error.BadVersion,
    };
}

fn encodeSigBlockV1(allocator: Allocator, signature: []const u8, payload_chunk: []const u8) ![]u8 {
    var arr = try Payload.arrPayload(2, allocator);
    errdefer arr.free(allocator);

    const sig_payload = try Payload.binToPayload(signature, allocator);
    try arr.setArrElement(0, sig_payload);

    const chunk_payload = try Payload.binToPayload(payload_chunk, allocator);
    try arr.setArrElement(1, chunk_payload);

    const data_len = signature.len + payload_chunk.len;
    return try serializePayload(allocator, arr, data_len);
}

fn encodeSigBlockV2(allocator: Allocator, signature: []const u8, payload_chunk: []const u8, is_final: bool) ![]u8 {
    var arr = try Payload.arrPayload(3, allocator);
    errdefer arr.free(allocator);

    try arr.setArrElement(0, Payload.boolToPayload(is_final));

    const sig_payload = try Payload.binToPayload(signature, allocator);
    try arr.setArrElement(1, sig_payload);

    const chunk_payload = try Payload.binToPayload(payload_chunk, allocator);
    try arr.setArrElement(2, chunk_payload);

    const data_len = signature.len + payload_chunk.len;
    return try serializePayload(allocator, arr, data_len);
}

/// Decode a signature block from a buffer.
const SigBlockDecodeResult = struct {
    signature: []u8,
    payload_chunk: []u8,
    is_final: bool,
    bytes_consumed: usize,
};

fn decodeSignatureBlockFromBuf(
    allocator: Allocator,
    data: []const u8,
    version: types.Version,
) !SigBlockDecodeResult {
    const max_buf: usize = 2 * types.signature_block_size + 4096;
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
        else => return sp_errors.Error.BadSignature,
    };

    return switch (version.major) {
        1 => try decodeSigBlkV1(allocator, arr_items, read_buf.pos),
        2 => try decodeSigBlkV2(allocator, arr_items, read_buf.pos),
        else => sp_errors.Error.BadVersion,
    };
}

fn decodeSigBlkV1(allocator: Allocator, arr_items: []Payload, bytes_consumed: usize) !SigBlockDecodeResult {
    if (arr_items.len != 2) return sp_errors.Error.BadSignature;

    const sig_bytes = switch (arr_items[0]) {
        .bin => |b| b.bin,
        else => return sp_errors.Error.BadSignature,
    };

    const chunk_bytes = switch (arr_items[1]) {
        .bin => |b| b.bin,
        else => return sp_errors.Error.BadSignature,
    };

    const sig_out = try allocator.alloc(u8, sig_bytes.len);
    errdefer allocator.free(sig_out);
    @memcpy(sig_out, sig_bytes);

    const chunk_out = try allocator.alloc(u8, chunk_bytes.len);
    errdefer allocator.free(chunk_out);
    @memcpy(chunk_out, chunk_bytes);

    return SigBlockDecodeResult{
        .signature = sig_out,
        .payload_chunk = chunk_out,
        .is_final = (chunk_bytes.len == 0),
        .bytes_consumed = bytes_consumed,
    };
}

fn decodeSigBlkV2(allocator: Allocator, arr_items: []Payload, bytes_consumed: usize) !SigBlockDecodeResult {
    if (arr_items.len != 3) return sp_errors.Error.BadSignature;

    const is_final = switch (arr_items[0]) {
        .bool => |b| b,
        else => return sp_errors.Error.BadSignature,
    };

    const sig_bytes = switch (arr_items[1]) {
        .bin => |b| b.bin,
        else => return sp_errors.Error.BadSignature,
    };

    const chunk_bytes = switch (arr_items[2]) {
        .bin => |b| b.bin,
        else => return sp_errors.Error.BadSignature,
    };

    const sig_out = try allocator.alloc(u8, sig_bytes.len);
    errdefer allocator.free(sig_out);
    @memcpy(sig_out, sig_bytes);

    const chunk_out = try allocator.alloc(u8, chunk_bytes.len);
    errdefer allocator.free(chunk_out);
    @memcpy(chunk_out, chunk_bytes);

    return SigBlockDecodeResult{
        .signature = sig_out,
        .payload_chunk = chunk_out,
        .is_final = is_final,
        .bytes_consumed = bytes_consumed,
    };
}

/// Serialize a msgpack Payload to heap-allocated bytes.
/// `payload_data_len` is the total size of the binary data contained in
/// the payload, used to compute a tight temporary buffer estimate.
fn serializePayload(allocator: Allocator, payload: Payload, payload_data_len: usize) ![]u8 {
    defer {
        var p = payload;
        p.free(allocator);
    }

    // Allocate a tight temporary buffer: actual data size plus overhead
    // for msgpack array/bin headers, booleans, etc.
    const buf_size = payload_data_len + 4096;
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

// ===========================================================================
// Tests
// ===========================================================================

const FBS = std.io.FixedBufferStream([]const u8);

/// Helper: collect all bytes from a stream reader into an allocated slice.
fn readAll(comptime StreamType: type, stream_ptr: *StreamType, allocator: Allocator) ![]u8 {
    var result: std.ArrayList(u8) = .empty;
    errdefer result.deinit(allocator);

    var buf: [4096]u8 = undefined;
    while (true) {
        const n = try stream_ptr.read(&buf);
        if (n == 0) break;
        try result.appendSlice(allocator, buf[0..n]);
    }
    return try result.toOwnedSlice(allocator);
}

/// Helper: write all bytes using an ArrayList-based writer.
const TestWriter = struct {
    list: *std.ArrayList(u8),
    alloc: Allocator,

    pub const Error = Allocator.Error;
    pub const WriteError = Allocator.Error;

    pub fn write(self: TestWriter, data: []const u8) WriteError!usize {
        self.list.appendSlice(self.alloc, data) catch |err| return err;
        return data.len;
    }

    pub fn writeAll(self: TestWriter, data: []const u8) WriteError!void {
        self.list.appendSlice(self.alloc, data) catch |err| return err;
    }
};

test "EncryptStream: basic V2 round-trip with DecryptStream" {
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();

    const msg = "hello streaming encryption!";

    // Encrypt via stream.
    var ct_list: std.ArrayList(u8) = .empty;
    defer ct_list.deinit(allocator);
    const tw = TestWriter{ .list = &ct_list, .alloc = allocator };

    var enc = try EncryptStream(TestWriter).init(
        allocator,
        tw,
        sender_kp.secret_key,
        &[_]key_mod.BoxPublicKey{receiver_kp.public_key},
        .{},
    );
    defer enc.deinit();

    _ = try enc.write(msg);
    try enc.finish();

    // Decrypt via stream.
    var fbs = std.io.fixedBufferStream(@as([]const u8, ct_list.items));
    const keyring = [_]key_mod.BoxKeyPair{receiver_kp};
    var dec = try DecryptStream(FBS.Reader).init(
        allocator,
        fbs.reader(),
        &keyring,
    );
    defer dec.deinit();

    const pt = try readAll(DecryptStream(FBS.Reader), &dec, allocator);
    defer allocator.free(pt);

    try std.testing.expectEqualStrings(msg, pt);
    try std.testing.expect(!dec.key_info.sender_is_anonymous);
}

test "EncryptStream: V2 empty message" {
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();

    var ct_list: std.ArrayList(u8) = .empty;
    defer ct_list.deinit(allocator);
    const tw = TestWriter{ .list = &ct_list, .alloc = allocator };

    var enc = try EncryptStream(TestWriter).init(
        allocator,
        tw,
        sender_kp.secret_key,
        &[_]key_mod.BoxPublicKey{receiver_kp.public_key},
        .{},
    );
    defer enc.deinit();

    try enc.finish();

    // Decrypt with one-shot API.
    const keyring = [_]key_mod.BoxKeyPair{receiver_kp};
    const result = try decrypt_mod.open(allocator, ct_list.items, &keyring, .{});
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 0), result.plaintext.len);
}

test "EncryptStream: V1 round-trip" {
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();

    const msg = "hello v1 streaming!";

    var ct_list: std.ArrayList(u8) = .empty;
    defer ct_list.deinit(allocator);
    const tw = TestWriter{ .list = &ct_list, .alloc = allocator };

    var enc = try EncryptStream(TestWriter).init(
        allocator,
        tw,
        sender_kp.secret_key,
        &[_]key_mod.BoxPublicKey{receiver_kp.public_key},
        .{ .version = types.Version.v1() },
    );
    defer enc.deinit();

    _ = try enc.write(msg);
    try enc.finish();

    const keyring = [_]key_mod.BoxKeyPair{receiver_kp};
    const result = try decrypt_mod.open(allocator, ct_list.items, &keyring, .{});
    defer result.deinit();

    try std.testing.expectEqualStrings(msg, result.plaintext);
}

test "EncryptStream: anonymous sender" {
    const allocator = std.testing.allocator;
    const receiver_kp = key_mod.BoxKeyPair.generate();

    var ct_list: std.ArrayList(u8) = .empty;
    defer ct_list.deinit(allocator);
    const tw = TestWriter{ .list = &ct_list, .alloc = allocator };

    var enc = try EncryptStream(TestWriter).init(
        allocator,
        tw,
        null,
        &[_]key_mod.BoxPublicKey{receiver_kp.public_key},
        .{},
    );
    defer enc.deinit();

    _ = try enc.write("anonymous stream");
    try enc.finish();

    const keyring = [_]key_mod.BoxKeyPair{receiver_kp};
    const result = try decrypt_mod.open(allocator, ct_list.items, &keyring, .{});
    defer result.deinit();

    try std.testing.expectEqualStrings("anonymous stream", result.plaintext);
    try std.testing.expect(result.key_info.sender_is_anonymous);
}

test "EncryptStream: multiple receivers" {
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const r1 = key_mod.BoxKeyPair.generate();
    const r2 = key_mod.BoxKeyPair.generate();

    var ct_list: std.ArrayList(u8) = .empty;
    defer ct_list.deinit(allocator);
    const tw = TestWriter{ .list = &ct_list, .alloc = allocator };

    var enc = try EncryptStream(TestWriter).init(
        allocator,
        tw,
        sender_kp.secret_key,
        &[_]key_mod.BoxPublicKey{ r1.public_key, r2.public_key },
        .{},
    );
    defer enc.deinit();

    _ = try enc.write("multi-receiver");
    try enc.finish();

    {
        const keyring = [_]key_mod.BoxKeyPair{r1};
        const result = try decrypt_mod.open(allocator, ct_list.items, &keyring, .{});
        defer result.deinit();
        try std.testing.expectEqualStrings("multi-receiver", result.plaintext);
    }
    {
        const keyring = [_]key_mod.BoxKeyPair{r2};
        const result = try decrypt_mod.open(allocator, ct_list.items, &keyring, .{});
        defer result.deinit();
        try std.testing.expectEqualStrings("multi-receiver", result.plaintext);
    }
}

test "EncryptStream: incremental writes" {
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();

    var ct_list: std.ArrayList(u8) = .empty;
    defer ct_list.deinit(allocator);
    const tw = TestWriter{ .list = &ct_list, .alloc = allocator };

    var enc = try EncryptStream(TestWriter).init(
        allocator,
        tw,
        sender_kp.secret_key,
        &[_]key_mod.BoxPublicKey{receiver_kp.public_key},
        .{},
    );
    defer enc.deinit();

    _ = try enc.write("hello ");
    _ = try enc.write("world ");
    _ = try enc.write("streaming!");
    try enc.finish();

    const keyring = [_]key_mod.BoxKeyPair{receiver_kp};
    const result = try decrypt_mod.open(allocator, ct_list.items, &keyring, .{});
    defer result.deinit();

    try std.testing.expectEqualStrings("hello world streaming!", result.plaintext);
}

test "EncryptStream: compatibility with one-shot decrypt" {
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();

    const msg = "stream-encrypted, one-shot-decrypted";

    var ct_list: std.ArrayList(u8) = .empty;
    defer ct_list.deinit(allocator);
    const tw = TestWriter{ .list = &ct_list, .alloc = allocator };

    var enc = try EncryptStream(TestWriter).init(
        allocator,
        tw,
        sender_kp.secret_key,
        &[_]key_mod.BoxPublicKey{receiver_kp.public_key},
        .{},
    );
    defer enc.deinit();

    _ = try enc.write(msg);
    try enc.finish();

    const keyring = [_]key_mod.BoxKeyPair{receiver_kp};
    const result = try decrypt_mod.open(allocator, ct_list.items, &keyring, .{});
    defer result.deinit();

    try std.testing.expectEqualStrings(msg, result.plaintext);
}

test "DecryptStream: compatibility with one-shot encrypt" {
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();

    const msg = "one-shot-encrypted, stream-decrypted";

    const ct = try encrypt_mod.seal(
        allocator,
        msg,
        sender_kp.secret_key,
        &[_]key_mod.BoxPublicKey{receiver_kp.public_key},
        .{},
    );
    defer allocator.free(ct);

    var fbs = std.io.fixedBufferStream(@as([]const u8, ct));
    const keyring = [_]key_mod.BoxKeyPair{receiver_kp};
    var dec = try DecryptStream(FBS.Reader).init(
        allocator,
        fbs.reader(),
        &keyring,
    );
    defer dec.deinit();

    const pt = try readAll(DecryptStream(FBS.Reader), &dec, allocator);
    defer allocator.free(pt);

    try std.testing.expectEqualStrings(msg, pt);
}

test "DecryptStream: V1 compatibility with one-shot encrypt" {
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();

    const msg = "v1 stream decrypt";

    const ct = try encrypt_mod.seal(
        allocator,
        msg,
        sender_kp.secret_key,
        &[_]key_mod.BoxPublicKey{receiver_kp.public_key},
        .{ .version = types.Version.v1() },
    );
    defer allocator.free(ct);

    var fbs = std.io.fixedBufferStream(@as([]const u8, ct));
    const keyring = [_]key_mod.BoxKeyPair{receiver_kp};
    var dec = try DecryptStream(FBS.Reader).init(
        allocator,
        fbs.reader(),
        &keyring,
    );
    defer dec.deinit();

    const pt = try readAll(DecryptStream(FBS.Reader), &dec, allocator);
    defer allocator.free(pt);

    try std.testing.expectEqualStrings(msg, pt);
}

test "DecryptStream: wrong key fails" {
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();
    const wrong_kp = key_mod.BoxKeyPair.generate();

    const ct = try encrypt_mod.seal(
        allocator,
        "test",
        sender_kp.secret_key,
        &[_]key_mod.BoxPublicKey{receiver_kp.public_key},
        .{},
    );
    defer allocator.free(ct);

    var fbs = std.io.fixedBufferStream(@as([]const u8, ct));
    const keyring = [_]key_mod.BoxKeyPair{wrong_kp};

    const result = DecryptStream(FBS.Reader).init(
        allocator,
        fbs.reader(),
        &keyring,
    );
    try std.testing.expectError(sp_errors.Error.NoDecryptionKey, result);
}

test "SignStream: basic V2 round-trip with VerifyStream" {
    const allocator = std.testing.allocator;
    const signer_kp = key_mod.SigningKeyPair.generate();

    const msg = "hello streaming signing!";

    var sig_list: std.ArrayList(u8) = .empty;
    defer sig_list.deinit(allocator);
    const tw = TestWriter{ .list = &sig_list, .alloc = allocator };

    var ss = try SignStream(TestWriter).init(
        allocator,
        tw,
        signer_kp.secret_key,
        .{},
    );
    defer ss.deinit();

    _ = try ss.write(msg);
    try ss.finish();

    var fbs = std.io.fixedBufferStream(@as([]const u8, sig_list.items));
    var vs = try VerifyStream(FBS.Reader).init(
        allocator,
        fbs.reader(),
    );
    defer vs.deinit();

    const pt = try readAll(VerifyStream(FBS.Reader), &vs, allocator);
    defer allocator.free(pt);

    try std.testing.expectEqualStrings(msg, pt);
    try std.testing.expect(vs.getSigner().eql(signer_kp.public_key));
}

test "SignStream: V2 empty message" {
    const allocator = std.testing.allocator;
    const signer_kp = key_mod.SigningKeyPair.generate();

    var sig_list: std.ArrayList(u8) = .empty;
    defer sig_list.deinit(allocator);
    const tw = TestWriter{ .list = &sig_list, .alloc = allocator };

    var ss = try SignStream(TestWriter).init(
        allocator,
        tw,
        signer_kp.secret_key,
        .{},
    );
    defer ss.deinit();

    try ss.finish();

    const result = try verify_mod.verify(allocator, sig_list.items);
    defer result.deinit();

    try std.testing.expectEqual(@as(usize, 0), result.plaintext.len);
    try std.testing.expect(result.signer.eql(signer_kp.public_key));
}

test "SignStream: V1 round-trip" {
    const allocator = std.testing.allocator;
    const signer_kp = key_mod.SigningKeyPair.generate();

    const msg = "hello v1 signing!";

    var sig_list: std.ArrayList(u8) = .empty;
    defer sig_list.deinit(allocator);
    const tw = TestWriter{ .list = &sig_list, .alloc = allocator };

    var ss = try SignStream(TestWriter).init(
        allocator,
        tw,
        signer_kp.secret_key,
        .{ .version = types.Version.v1() },
    );
    defer ss.deinit();

    _ = try ss.write(msg);
    try ss.finish();

    const result = try verify_mod.verify(allocator, sig_list.items);
    defer result.deinit();

    try std.testing.expectEqualStrings(msg, result.plaintext);
    try std.testing.expect(result.signer.eql(signer_kp.public_key));
}

test "SignStream: incremental writes" {
    const allocator = std.testing.allocator;
    const signer_kp = key_mod.SigningKeyPair.generate();

    var sig_list: std.ArrayList(u8) = .empty;
    defer sig_list.deinit(allocator);
    const tw = TestWriter{ .list = &sig_list, .alloc = allocator };

    var ss = try SignStream(TestWriter).init(
        allocator,
        tw,
        signer_kp.secret_key,
        .{},
    );
    defer ss.deinit();

    _ = try ss.write("piece1 ");
    _ = try ss.write("piece2 ");
    _ = try ss.write("piece3");
    try ss.finish();

    const result = try verify_mod.verify(allocator, sig_list.items);
    defer result.deinit();

    try std.testing.expectEqualStrings("piece1 piece2 piece3", result.plaintext);
}

test "SignStream: compatibility with one-shot verify" {
    const allocator = std.testing.allocator;
    const signer_kp = key_mod.SigningKeyPair.generate();

    const msg = "stream-signed, one-shot-verified";

    var sig_list: std.ArrayList(u8) = .empty;
    defer sig_list.deinit(allocator);
    const tw = TestWriter{ .list = &sig_list, .alloc = allocator };

    var ss = try SignStream(TestWriter).init(
        allocator,
        tw,
        signer_kp.secret_key,
        .{},
    );
    defer ss.deinit();

    _ = try ss.write(msg);
    try ss.finish();

    const result = try verify_mod.verify(allocator, sig_list.items);
    defer result.deinit();

    try std.testing.expectEqualStrings(msg, result.plaintext);
}

test "VerifyStream: compatibility with one-shot sign" {
    const allocator = std.testing.allocator;
    const signer_kp = key_mod.SigningKeyPair.generate();

    const msg = "one-shot-signed, stream-verified";

    const signed = try sign_mod.sign(allocator, msg, signer_kp.secret_key, .{});
    defer signed.deinit();

    var fbs = std.io.fixedBufferStream(signed.data);
    var vs = try VerifyStream(FBS.Reader).init(
        allocator,
        fbs.reader(),
    );
    defer vs.deinit();

    const pt = try readAll(VerifyStream(FBS.Reader), &vs, allocator);
    defer allocator.free(pt);

    try std.testing.expectEqualStrings(msg, pt);
    try std.testing.expect(vs.getSigner().eql(signer_kp.public_key));
}

test "VerifyStream: V1 compatibility with one-shot sign" {
    const allocator = std.testing.allocator;
    const signer_kp = key_mod.SigningKeyPair.generate();

    const msg = "v1 stream verify";

    const signed = try sign_mod.sign(allocator, msg, signer_kp.secret_key, .{ .version = types.Version.v1() });
    defer signed.deinit();

    var fbs = std.io.fixedBufferStream(signed.data);
    var vs = try VerifyStream(FBS.Reader).init(
        allocator,
        fbs.reader(),
    );
    defer vs.deinit();

    const pt = try readAll(VerifyStream(FBS.Reader), &vs, allocator);
    defer allocator.free(pt);

    try std.testing.expectEqualStrings(msg, pt);
}

test "EncryptStream rejects zero receivers" {
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();

    var ct_list: std.ArrayList(u8) = .empty;
    defer ct_list.deinit(allocator);
    const tw = TestWriter{ .list = &ct_list, .alloc = allocator };

    const result = EncryptStream(TestWriter).init(
        allocator,
        tw,
        sender_kp.secret_key,
        &[_]key_mod.BoxPublicKey{},
        .{},
    );
    try std.testing.expectError(sp_errors.Error.BadReceivers, result);
}

test "EncryptStream rejects duplicate receivers" {
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();

    var ct_list: std.ArrayList(u8) = .empty;
    defer ct_list.deinit(allocator);
    const tw = TestWriter{ .list = &ct_list, .alloc = allocator };

    const result = EncryptStream(TestWriter).init(
        allocator,
        tw,
        sender_kp.secret_key,
        &[_]key_mod.BoxPublicKey{ receiver_kp.public_key, receiver_kp.public_key },
        .{},
    );
    try std.testing.expectError(sp_errors.Error.RepeatedKey, result);
}

test "full round-trip: EncryptStream -> DecryptStream with various sizes" {
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();

    const sizes = [_]usize{ 0, 1, 10, 100, 1000, 4096, 10000 };

    for (sizes) |size| {
        const msg = try allocator.alloc(u8, size);
        defer allocator.free(msg);
        @memset(msg, 0x42);

        var ct_list: std.ArrayList(u8) = .empty;
        defer ct_list.deinit(allocator);
        const tw = TestWriter{ .list = &ct_list, .alloc = allocator };

        var enc = try EncryptStream(TestWriter).init(
            allocator,
            tw,
            sender_kp.secret_key,
            &[_]key_mod.BoxPublicKey{receiver_kp.public_key},
            .{},
        );
        defer enc.deinit();

        _ = try enc.write(msg);
        try enc.finish();

        var fbs = std.io.fixedBufferStream(@as([]const u8, ct_list.items));
        const keyring = [_]key_mod.BoxKeyPair{receiver_kp};
        var dec = try DecryptStream(FBS.Reader).init(
            allocator,
            fbs.reader(),
            &keyring,
        );
        defer dec.deinit();

        const pt = try readAll(DecryptStream(FBS.Reader), &dec, allocator);
        defer allocator.free(pt);

        try std.testing.expectEqual(size, pt.len);
        if (size > 0) {
            try std.testing.expectEqualSlices(u8, msg, pt);
        }
    }
}

test "full round-trip: SignStream -> VerifyStream with various sizes" {
    const allocator = std.testing.allocator;
    const signer_kp = key_mod.SigningKeyPair.generate();

    const sizes = [_]usize{ 0, 1, 10, 100, 1000, 4096, 10000 };

    for (sizes) |size| {
        const msg = try allocator.alloc(u8, size);
        defer allocator.free(msg);
        @memset(msg, 0x55);

        var sig_list: std.ArrayList(u8) = .empty;
        defer sig_list.deinit(allocator);
        const tw = TestWriter{ .list = &sig_list, .alloc = allocator };

        var ss = try SignStream(TestWriter).init(
            allocator,
            tw,
            signer_kp.secret_key,
            .{},
        );
        defer ss.deinit();

        _ = try ss.write(msg);
        try ss.finish();

        var fbs = std.io.fixedBufferStream(@as([]const u8, sig_list.items));
        var vs = try VerifyStream(FBS.Reader).init(
            allocator,
            fbs.reader(),
        );
        defer vs.deinit();

        const pt = try readAll(VerifyStream(FBS.Reader), &vs, allocator);
        defer allocator.free(pt);

        try std.testing.expectEqual(size, pt.len);
        if (size > 0) {
            try std.testing.expectEqualSlices(u8, msg, pt);
        }
    }
}

test "encryptStream convenience function" {
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();

    var ct_list: std.ArrayList(u8) = .empty;
    defer ct_list.deinit(allocator);
    const tw = TestWriter{ .list = &ct_list, .alloc = allocator };

    var enc = try encryptStream(
        allocator,
        tw,
        sender_kp.secret_key,
        &[_]key_mod.BoxPublicKey{receiver_kp.public_key},
        .{},
    );
    defer enc.deinit();

    _ = try enc.write("convenience");
    try enc.finish();

    const keyring = [_]key_mod.BoxKeyPair{receiver_kp};
    const result = try decrypt_mod.open(allocator, ct_list.items, &keyring, .{});
    defer result.deinit();

    try std.testing.expectEqualStrings("convenience", result.plaintext);
}

test "decryptStream convenience function" {
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();

    const ct = try encrypt_mod.seal(
        allocator,
        "convenience",
        sender_kp.secret_key,
        &[_]key_mod.BoxPublicKey{receiver_kp.public_key},
        .{},
    );
    defer allocator.free(ct);

    var fbs = std.io.fixedBufferStream(@as([]const u8, ct));
    const keyring = [_]key_mod.BoxKeyPair{receiver_kp};

    var dec = try decryptStream(allocator, fbs.reader(), &keyring);
    defer dec.deinit();

    const pt = try readAll(@TypeOf(dec), &dec, allocator);
    defer allocator.free(pt);

    try std.testing.expectEqualStrings("convenience", pt);
}

test "signStream convenience function" {
    const allocator = std.testing.allocator;
    const signer_kp = key_mod.SigningKeyPair.generate();

    var sig_list: std.ArrayList(u8) = .empty;
    defer sig_list.deinit(allocator);
    const tw = TestWriter{ .list = &sig_list, .alloc = allocator };

    var ss = try signStream(allocator, tw, signer_kp.secret_key, .{});
    defer ss.deinit();

    _ = try ss.write("convenience");
    try ss.finish();

    const result = try verify_mod.verify(allocator, sig_list.items);
    defer result.deinit();

    try std.testing.expectEqualStrings("convenience", result.plaintext);
}

test "verifyStream convenience function" {
    const allocator = std.testing.allocator;
    const signer_kp = key_mod.SigningKeyPair.generate();

    const signed = try sign_mod.sign(allocator, "convenience", signer_kp.secret_key, .{});
    defer signed.deinit();

    var fbs = std.io.fixedBufferStream(signed.data);

    var vs = try verifyStream(allocator, fbs.reader());
    defer vs.deinit();

    const pt = try readAll(@TypeOf(vs), &vs, allocator);
    defer allocator.free(pt);

    try std.testing.expectEqualStrings("convenience", pt);
}

test "EncryptStream: double-finish returns StreamAlreadyFinished" {
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();

    var ct_list: std.ArrayList(u8) = .empty;
    defer ct_list.deinit(allocator);
    const tw = TestWriter{ .list = &ct_list, .alloc = allocator };

    var enc = try EncryptStream(TestWriter).init(
        allocator,
        tw,
        sender_kp.secret_key,
        &[_]key_mod.BoxPublicKey{receiver_kp.public_key},
        .{},
    );
    defer enc.deinit();

    _ = try enc.write("data");
    try enc.finish();

    // Second finish should fail.
    try std.testing.expectError(error.StreamAlreadyFinished, enc.finish());
}

test "EncryptStream: write-after-finish returns StreamAlreadyFinished" {
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();

    var ct_list: std.ArrayList(u8) = .empty;
    defer ct_list.deinit(allocator);
    const tw = TestWriter{ .list = &ct_list, .alloc = allocator };

    var enc = try EncryptStream(TestWriter).init(
        allocator,
        tw,
        sender_kp.secret_key,
        &[_]key_mod.BoxPublicKey{receiver_kp.public_key},
        .{},
    );
    defer enc.deinit();

    _ = try enc.write("data");
    try enc.finish();

    // Write after finish should fail.
    try std.testing.expectError(error.StreamAlreadyFinished, enc.write("more"));
}

test "SignStream: double-finish returns StreamAlreadyFinished" {
    const allocator = std.testing.allocator;
    const signer_kp = key_mod.SigningKeyPair.generate();

    var sig_list: std.ArrayList(u8) = .empty;
    defer sig_list.deinit(allocator);
    const tw = TestWriter{ .list = &sig_list, .alloc = allocator };

    var ss = try SignStream(TestWriter).init(
        allocator,
        tw,
        signer_kp.secret_key,
        .{},
    );
    defer ss.deinit();

    _ = try ss.write("data");
    try ss.finish();

    // Second finish should fail.
    try std.testing.expectError(error.StreamAlreadyFinished, ss.finish());
}

test "SignStream: write-after-finish returns StreamAlreadyFinished" {
    const allocator = std.testing.allocator;
    const signer_kp = key_mod.SigningKeyPair.generate();

    var sig_list: std.ArrayList(u8) = .empty;
    defer sig_list.deinit(allocator);
    const tw = TestWriter{ .list = &sig_list, .alloc = allocator };

    var ss = try SignStream(TestWriter).init(
        allocator,
        tw,
        signer_kp.secret_key,
        .{},
    );
    defer ss.deinit();

    _ = try ss.write("data");
    try ss.finish();

    // Write after finish should fail.
    try std.testing.expectError(error.StreamAlreadyFinished, ss.write("more"));
}

// ---------------------------------------------------------------------------
// setMaxBytes enforcement tests
// ---------------------------------------------------------------------------

test "EncryptStream: setMaxBytes rejects writes exceeding limit" {
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();

    var ct_list: std.ArrayList(u8) = .empty;
    defer ct_list.deinit(allocator);
    const tw = TestWriter{ .list = &ct_list, .alloc = allocator };

    var enc = try EncryptStream(TestWriter).init(
        allocator,
        tw,
        sender_kp.secret_key,
        &[_]key_mod.BoxPublicKey{receiver_kp.public_key},
        .{},
    );
    defer enc.deinit();

    enc.setMaxBytes(100);

    // Write more than 100 bytes.
    const big_data = [_]u8{0x42} ** 150;
    try std.testing.expectError(error.MaxMessageSizeExceeded, enc.write(&big_data));
}

test "SignStream: setMaxBytes rejects writes exceeding limit" {
    const allocator = std.testing.allocator;
    const signer_kp = key_mod.SigningKeyPair.generate();

    var sig_list: std.ArrayList(u8) = .empty;
    defer sig_list.deinit(allocator);
    const tw = TestWriter{ .list = &sig_list, .alloc = allocator };

    var ss = try SignStream(TestWriter).init(
        allocator,
        tw,
        signer_kp.secret_key,
        .{},
    );
    defer ss.deinit();

    ss.setMaxBytes(50);

    // Write more than 50 bytes.
    const big_data = [_]u8{0x55} ** 80;
    try std.testing.expectError(error.MaxMessageSizeExceeded, ss.write(&big_data));
}

test "DecryptStream: setMaxBytes rejects reads exceeding limit" {
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();

    // Encrypt a message with enough data.
    const msg = "this message has more than one byte of plaintext data";
    const ct = try encrypt_mod.seal(
        allocator,
        msg,
        sender_kp.secret_key,
        &[_]key_mod.BoxPublicKey{receiver_kp.public_key},
        .{},
    );
    defer allocator.free(ct);

    var fbs = std.io.fixedBufferStream(@as([]const u8, ct));
    const keyring = [_]key_mod.BoxKeyPair{receiver_kp};
    var dec = try DecryptStream(FBS.Reader).init(
        allocator,
        fbs.reader(),
        &keyring,
    );
    defer dec.deinit();

    dec.setMaxBytes(1);

    // Try to read -- should exceed the limit.
    var buf: [4096]u8 = undefined;
    try std.testing.expectError(error.MaxMessageSizeExceeded, dec.read(&buf));
}

test "VerifyStream: setMaxBytes rejects reads exceeding limit" {
    const allocator = std.testing.allocator;
    const signer_kp = key_mod.SigningKeyPair.generate();

    const msg = "this signed message has more than one byte of plaintext data";
    const signed = try sign_mod.sign(allocator, msg, signer_kp.secret_key, .{});
    defer signed.deinit();

    var fbs = std.io.fixedBufferStream(signed.data);
    var vs = try VerifyStream(FBS.Reader).init(
        allocator,
        fbs.reader(),
    );
    defer vs.deinit();

    vs.setMaxBytes(1);

    // Try to read -- should exceed the limit.
    var buf: [4096]u8 = undefined;
    try std.testing.expectError(error.MaxMessageSizeExceeded, vs.read(&buf));
}

// ---------------------------------------------------------------------------
// Partial reads tests
// ---------------------------------------------------------------------------

test "DecryptStream: partial reads 1 byte at a time" {
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();

    // Create a ~1000 byte message.
    const msg = try allocator.alloc(u8, 1000);
    defer allocator.free(msg);
    @memset(msg, 0xAB);

    const ct = try encrypt_mod.seal(
        allocator,
        msg,
        sender_kp.secret_key,
        &[_]key_mod.BoxPublicKey{receiver_kp.public_key},
        .{},
    );
    defer allocator.free(ct);

    var fbs = std.io.fixedBufferStream(@as([]const u8, ct));
    const keyring = [_]key_mod.BoxKeyPair{receiver_kp};
    var dec = try DecryptStream(FBS.Reader).init(
        allocator,
        fbs.reader(),
        &keyring,
    );
    defer dec.deinit();

    // Read 1 byte at a time.
    var result: std.ArrayList(u8) = .empty;
    defer result.deinit(allocator);

    var one_buf: [1]u8 = undefined;
    while (true) {
        const n = try dec.read(&one_buf);
        if (n == 0) break;
        try result.appendSlice(allocator, one_buf[0..n]);
    }

    try std.testing.expectEqual(@as(usize, 1000), result.items.len);
    try std.testing.expectEqualSlices(u8, msg, result.items);
}

test "VerifyStream: partial reads 10 bytes at a time" {
    const allocator = std.testing.allocator;
    const signer_kp = key_mod.SigningKeyPair.generate();

    // Create a ~1000 byte message.
    const msg = try allocator.alloc(u8, 1000);
    defer allocator.free(msg);
    @memset(msg, 0xCD);

    const signed = try sign_mod.sign(allocator, msg, signer_kp.secret_key, .{});
    defer signed.deinit();

    var fbs = std.io.fixedBufferStream(signed.data);
    var vs = try VerifyStream(FBS.Reader).init(
        allocator,
        fbs.reader(),
    );
    defer vs.deinit();

    // Read 10 bytes at a time.
    var result: std.ArrayList(u8) = .empty;
    defer result.deinit(allocator);

    var ten_buf: [10]u8 = undefined;
    while (true) {
        const n = try vs.read(&ten_buf);
        if (n == 0) break;
        try result.appendSlice(allocator, ten_buf[0..n]);
    }

    try std.testing.expectEqual(@as(usize, 1000), result.items.len);
    try std.testing.expectEqualSlices(u8, msg, result.items);
}

// ---------------------------------------------------------------------------
// Read-after-EOF tests
// ---------------------------------------------------------------------------

test "DecryptStream: read after EOF returns 0" {
    const allocator = std.testing.allocator;
    const sender_kp = key_mod.BoxKeyPair.generate();
    const receiver_kp = key_mod.BoxKeyPair.generate();

    const msg = "read after eof test";
    const ct = try encrypt_mod.seal(
        allocator,
        msg,
        sender_kp.secret_key,
        &[_]key_mod.BoxPublicKey{receiver_kp.public_key},
        .{},
    );
    defer allocator.free(ct);

    var fbs = std.io.fixedBufferStream(@as([]const u8, ct));
    const keyring = [_]key_mod.BoxKeyPair{receiver_kp};
    var dec = try DecryptStream(FBS.Reader).init(
        allocator,
        fbs.reader(),
        &keyring,
    );
    defer dec.deinit();

    // Read all data.
    const pt = try readAll(DecryptStream(FBS.Reader), &dec, allocator);
    defer allocator.free(pt);
    try std.testing.expectEqualStrings(msg, pt);

    // Read again after EOF -- should return 0.
    var buf: [64]u8 = undefined;
    const n = try dec.read(&buf);
    try std.testing.expectEqual(@as(usize, 0), n);
}

test "VerifyStream: read after EOF returns 0" {
    const allocator = std.testing.allocator;
    const signer_kp = key_mod.SigningKeyPair.generate();

    const msg = "read after eof verify test";
    const signed = try sign_mod.sign(allocator, msg, signer_kp.secret_key, .{});
    defer signed.deinit();

    var fbs = std.io.fixedBufferStream(signed.data);
    var vs = try VerifyStream(FBS.Reader).init(
        allocator,
        fbs.reader(),
    );
    defer vs.deinit();

    // Read all data.
    const pt = try readAll(VerifyStream(FBS.Reader), &vs, allocator);
    defer allocator.free(pt);
    try std.testing.expectEqualStrings(msg, pt);

    // Read again after EOF -- should return 0.
    var buf: [64]u8 = undefined;
    const n = try vs.read(&buf);
    try std.testing.expectEqual(@as(usize, 0), n);
}
