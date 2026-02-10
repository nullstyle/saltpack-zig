//! BaseX encoding/decoding with fixed-buffer big-integer arithmetic.
//!
//! Implements the BaseX encoding scheme used by saltpack's armor format.
//! The default configuration uses Base62 with 32-byte input blocks
//! producing 43-character output blocks.
//!
//! All big-integer arithmetic uses stack-allocated fixed-size limb arrays
//! sized at comptime, eliminating heap allocations from encode/decode.

const std = @import("std");
const math = std.math;
const testing = std.testing;
const mem = std.mem;
const Allocator = std.mem.Allocator;
const Limb = std.math.big.Limb;
const DoubleLimb = std.math.big.DoubleLimb;

const limb_bits = @bitSizeOf(Limb);
const limb_bytes = limb_bits / 8;

/// Errors that can occur during BaseX encoding/decoding.
pub const Error = error{
    /// The decoded value overflows the expected byte count.
    Overflow,
    /// An invalid character was encountered in the input.
    InvalidCharacter,
    /// The encoding length is non-minimal (invalid block size).
    InvalidEncodingLength,
};

/// A BaseX encoding parameterized by alphabet and block size at comptime.
pub fn Encoding(comptime alphabet: []const u8, comptime bytes_per_block: comptime_int) type {
    const base: comptime_int = alphabet.len;
    const log2_of_base: comptime_float = @log2(@as(f64, @floatFromInt(base)));
    const chars_per_block: comptime_int = blk: {
        break :blk @as(comptime_int, @intFromFloat(@ceil(@as(f64, @floatFromInt(bytes_per_block * 8)) / log2_of_base)));
    };

    return struct {
        const Self = @This();

        // Build a decode map at comptime: maps byte -> digit value, 0xFF means invalid
        const decode_map: [256]u8 = blk: {
            var map_arr: [256]u8 = [_]u8{0xFF} ** 256;
            for (alphabet, 0..) |ch, i| {
                map_arr[ch] = @intCast(i);
            }
            break :blk map_arr;
        };

        // Maximum number of limbs needed to represent bytes_per_block bytes.
        // Add 1 extra limb for intermediate multiply overflow.
        const max_limbs: comptime_int = (bytes_per_block * 8 + limb_bits - 1) / limb_bits + 1;

        /// Returns the number of encoded characters for `n` input bytes.
        pub fn encodedLen(n: usize) usize {
            if (n == 0) return 0;
            const nblocks = n / bytes_per_block;
            var out = nblocks * chars_per_block;
            const remainder = n % bytes_per_block;
            if (remainder > 0) {
                out += @as(usize, @intFromFloat(@ceil(@as(f64, @floatFromInt(remainder * 8)) / log2_of_base)));
            }
            return out;
        }

        /// Returns the number of decoded bytes for `n` input characters.
        pub fn decodedLen(n: usize) usize {
            if (n == 0) return 0;
            const nblocks = n / chars_per_block;
            var out = nblocks * bytes_per_block;
            const remainder = n % chars_per_block;
            if (remainder > 0) {
                out += @as(usize, @intFromFloat(@floor(@as(f64, @floatFromInt(remainder)) * log2_of_base / 8.0)));
            }
            return out;
        }

        /// Returns true if `n` is a valid encoding length for a (possibly short) block.
        pub fn isValidEncodingLength(n: usize) bool {
            if (n == chars_per_block) return true;
            if (n == 0) return true;
            const f = struct {
                fn compute(val: usize) usize {
                    return @as(usize, @intFromFloat(@floor(@as(f64, @floatFromInt(val)) * log2_of_base / 8.0)));
                }
            };
            return f.compute(n) != f.compute(n - 1);
        }

        /// Fixed-size big integer using stack-allocated limb array.
        /// Stores a non-negative integer in little-endian limb order.
        const FixedBigInt = struct {
            limbs: [max_limbs]Limb,
            len: usize, // number of limbs currently in use (at least 1)

            fn zero() FixedBigInt {
                var result: FixedBigInt = undefined;
                result.limbs[0] = 0;
                result.len = 1;
                return result;
            }

            fn isZero(self: *const FixedBigInt) bool {
                return self.len == 1 and self.limbs[0] == 0;
            }

            /// Set from big-endian byte slice (interprets bytes as unsigned big-endian integer).
            fn setFromBytesBigEndian(self: *FixedBigInt, bytes: []const u8) void {
                // Zero out all limbs
                @memset(&self.limbs, 0);

                // Pack bytes into limbs in little-endian limb order.
                // bytes[0] is the most significant byte.
                for (bytes, 0..) |byte_val, byte_idx| {
                    // Position of this byte in the integer (0 = least significant)
                    const pos = bytes.len - 1 - byte_idx;
                    const limb_index = pos / limb_bytes;
                    const byte_offset = pos % limb_bytes;
                    self.limbs[limb_index] |= @as(Limb, byte_val) << @intCast(byte_offset * 8);
                }

                // Normalize length
                self.len = 1;
                for (0..max_limbs) |i| {
                    const ri = max_limbs - 1 - i;
                    if (self.limbs[ri] != 0) {
                        self.len = ri + 1;
                        break;
                    }
                }
            }

            /// Multiply in-place by a small single-limb value.
            fn mulSmall(self: *FixedBigInt, factor: Limb) void {
                if (factor == 0) {
                    self.limbs[0] = 0;
                    self.len = 1;
                    return;
                }
                var carry: Limb = 0;
                for (0..self.len) |i| {
                    const wide: DoubleLimb = @as(DoubleLimb, self.limbs[i]) * @as(DoubleLimb, factor) + @as(DoubleLimb, carry);
                    self.limbs[i] = @truncate(wide);
                    carry = @intCast(wide >> limb_bits);
                }
                if (carry != 0) {
                    self.limbs[self.len] = carry;
                    self.len += 1;
                }
            }

            /// Add a small single-limb value in-place.
            fn addSmall(self: *FixedBigInt, val: Limb) void {
                var carry: Limb = val;
                for (0..self.len) |i| {
                    const sum: DoubleLimb = @as(DoubleLimb, self.limbs[i]) + @as(DoubleLimb, carry);
                    self.limbs[i] = @truncate(sum);
                    carry = @intCast(sum >> limb_bits);
                    if (carry == 0) return;
                }
                if (carry != 0) {
                    self.limbs[self.len] = carry;
                    self.len += 1;
                }
            }

            /// Divide in-place by a small single-limb divisor, returning the remainder.
            fn divSmall(self: *FixedBigInt, divisor: Limb) Limb {
                var rem: Limb = 0;
                // Process from most significant limb to least
                var i: usize = self.len;
                while (i > 0) {
                    i -= 1;
                    const wide: DoubleLimb = (@as(DoubleLimb, rem) << limb_bits) | @as(DoubleLimb, self.limbs[i]);
                    self.limbs[i] = @intCast(wide / @as(DoubleLimb, divisor));
                    rem = @intCast(wide % @as(DoubleLimb, divisor));
                }
                // Normalize length
                while (self.len > 1 and self.limbs[self.len - 1] == 0) {
                    self.len -= 1;
                }
                return rem;
            }

            /// Write the value as big-endian bytes into the output buffer.
            /// Returns the number of significant bytes (without leading zeros),
            /// or 0 if the value is zero. Output is left-padded with zeros
            /// to fill out_len bytes.
            fn toBytesBigEndian(self: *const FixedBigInt, output: []u8, out_len: usize) struct { total_bytes: usize, overflow: bool } {
                if (self.isZero()) {
                    @memset(output[0..out_len], 0);
                    return .{ .total_bytes = 0, .overflow = false };
                }

                // Calculate the number of significant bytes
                const top_limb = self.limbs[self.len - 1];
                var top_bytes: usize = 0;
                {
                    var tmp = top_limb;
                    while (tmp > 0) : (tmp >>= 8) {
                        top_bytes += 1;
                    }
                }
                const total_bytes = (self.len - 1) * limb_bytes + top_bytes;

                if (total_bytes > out_len) {
                    return .{ .total_bytes = total_bytes, .overflow = true };
                }

                // Zero-pad on the left
                const pad = out_len - total_bytes;
                @memset(output[0..pad], 0);

                // Write bytes in big-endian order
                var idx: usize = pad;

                // Top limb (partial bytes)
                {
                    var shift_amount: usize = (top_bytes - 1) * 8;
                    for (0..top_bytes) |_| {
                        output[idx] = @truncate(top_limb >> @intCast(shift_amount));
                        idx += 1;
                        if (shift_amount >= 8) {
                            shift_amount -= 8;
                        }
                    }
                }

                // Remaining full limbs, from high to low
                if (self.len > 1) {
                    var limb_i: usize = self.len - 1;
                    while (limb_i > 0) {
                        limb_i -= 1;
                        const limb = self.limbs[limb_i];
                        var shift_amount: usize = (limb_bytes - 1) * 8;
                        for (0..limb_bytes) |_| {
                            output[idx] = @truncate(limb >> @intCast(shift_amount));
                            idx += 1;
                            if (shift_amount >= 8) {
                                shift_amount -= 8;
                            }
                        }
                    }
                }

                return .{ .total_bytes = total_bytes, .overflow = false };
            }
        };

        /// Encode a single block of input bytes into output characters.
        /// Returns the number of characters written to `output`.
        /// This function performs zero heap allocations.
        pub fn encodeBlock(_: Allocator, input: []const u8, output: []u8) !usize {
            const enc_len = encodedLen(input.len);
            if (output.len < enc_len) return error.NoSpaceLeft;

            // Interpret input as big-endian unsigned integer using stack-allocated limbs
            var num = FixedBigInt.zero();
            num.setFromBytesBigEndian(input);

            // Repeatedly divide by base, collecting remainders (fills output right-to-left)
            var p: usize = enc_len;

            while (!num.isZero()) {
                const r = num.divSmall(@intCast(base));
                p -= 1;
                output[p] = alphabet[@intCast(r)];
            }

            // Pad with zero character
            while (p > 0) {
                p -= 1;
                output[p] = alphabet[0];
            }

            return enc_len;
        }

        /// Decode a single block of encoded characters into output bytes.
        /// Returns the number of bytes written to `output`.
        /// This function performs zero heap allocations.
        pub fn decodeBlock(_: Allocator, input: []const u8, output: []u8) !usize {
            if (input.len == 0) return 0;

            if (!isValidEncodingLength(input.len)) {
                return Error.InvalidEncodingLength;
            }

            const dec_len = decodedLen(input.len);
            if (output.len < dec_len) return error.NoSpaceLeft;

            // Horner's method: accumulate digits using stack-allocated big integer
            var num = FixedBigInt.zero();

            for (input) |ch| {
                const digit = decode_map[ch];
                if (digit == 0xFF) {
                    return Error.InvalidCharacter;
                }

                // num = num * base + digit
                num.mulSmall(@intCast(base));
                num.addSmall(@intCast(digit));
            }

            // Serialize as big-endian bytes directly into output
            const result = num.toBytesBigEndian(output, dec_len);
            if (result.overflow) {
                return Error.Overflow;
            }

            return dec_len;
        }

        /// Encode a multi-block input. Splits input into block-sized chunks.
        pub fn encode(allocator: Allocator, input: []const u8, output: []u8) !usize {
            var sp: usize = 0;
            var dp: usize = 0;

            while (sp < input.len) {
                const s_end = @min(sp + bytes_per_block, input.len);
                const chunk = input[sp..s_end];
                const enc_len = encodedLen(chunk.len);
                _ = try encodeBlock(allocator, chunk, output[dp..]);
                dp += enc_len;
                sp = s_end;
            }

            return dp;
        }

        /// Decode a multi-block input. Splits input into block-sized chunks.
        pub fn decode(allocator: Allocator, input: []const u8, output: []u8) !usize {
            var sp: usize = 0;
            var dp: usize = 0;

            while (sp < input.len) {
                const s_end = @min(sp + chars_per_block, input.len);
                const chunk = input[sp..s_end];
                const written = try decodeBlock(allocator, chunk, output[dp..]);
                dp += written;
                sp = s_end;
            }

            return dp;
        }

        // ---- Streaming types ----

        /// A streaming encoder that wraps an `AnyWriter`.
        /// Write raw bytes to this; it buffers them and emits encoded blocks.
        pub const Encoder = struct {
            inner: std.io.AnyWriter,
            allocator: Allocator,
            buf: [bytes_per_block]u8,
            nbuf: usize,
            out_buf: [chars_per_block * 4]u8,

            pub fn init(alloc: Allocator, w: std.io.AnyWriter) Encoder {
                return .{
                    .inner = w,
                    .allocator = alloc,
                    .buf = undefined,
                    .nbuf = 0,
                    .out_buf = undefined,
                };
            }

            pub fn write(self: *Encoder, data: []const u8) !usize {
                var p = data;
                var n: usize = 0;

                // Leading fringe: fill buffer
                if (self.nbuf > 0) {
                    while (p.len > 0 and self.nbuf < bytes_per_block) {
                        self.buf[self.nbuf] = p[0];
                        self.nbuf += 1;
                        p = p[1..];
                        n += 1;
                    }
                    if (self.nbuf < bytes_per_block) {
                        return n;
                    }
                    // Buffer is full, encode and flush
                    const written = try encodeBlock(self.allocator, &self.buf, &self.out_buf);
                    try self.inner.writeAll(self.out_buf[0..written]);
                    self.nbuf = 0;
                }

                // Full blocks
                while (p.len >= bytes_per_block) {
                    const written = try encodeBlock(self.allocator, p[0..bytes_per_block], &self.out_buf);
                    try self.inner.writeAll(self.out_buf[0..written]);
                    n += bytes_per_block;
                    p = p[bytes_per_block..];
                }

                // Trailing fringe
                if (p.len > 0) {
                    @memcpy(self.buf[0..p.len], p);
                    self.nbuf = p.len;
                    n += p.len;
                }

                return n;
            }

            /// Flush any remaining buffered data as a short block.
            pub fn finish(self: *Encoder) !void {
                if (self.nbuf > 0) {
                    const written = try encodeBlock(self.allocator, self.buf[0..self.nbuf], &self.out_buf);
                    try self.inner.writeAll(self.out_buf[0..written]);
                    self.nbuf = 0;
                }
            }
        };

        /// A streaming decoder that wraps an `AnyReader`.
        /// Read from this to get decoded bytes; it reads encoded characters from the inner reader.
        pub const Decoder = struct {
            inner: std.io.AnyReader,
            allocator: Allocator,
            char_buf: [chars_per_block * 128]u8,
            nchar: usize,
            out_buf: [bytes_per_block * 128]u8,
            out_start: usize,
            out_end: usize,
            eof: bool,

            pub fn init(alloc: Allocator, r: std.io.AnyReader) Decoder {
                return .{
                    .inner = r,
                    .allocator = alloc,
                    .char_buf = undefined,
                    .nchar = 0,
                    .out_buf = undefined,
                    .out_start = 0,
                    .out_end = 0,
                    .eof = false,
                };
            }

            pub fn read(self: *Decoder, dest: []u8) !usize {
                // Return leftover decoded data first
                if (self.out_start < self.out_end) {
                    const avail = self.out_end - self.out_start;
                    const to_copy = @min(avail, dest.len);
                    @memcpy(dest[0..to_copy], self.out_buf[self.out_start .. self.out_start + to_copy]);
                    self.out_start += to_copy;
                    return to_copy;
                }

                if (self.eof) return 0;

                // Try to read at least one full block of characters
                while (self.nchar < chars_per_block and !self.eof) {
                    const end = @min(self.nchar + chars_per_block, self.char_buf.len);
                    const space = self.char_buf[self.nchar..end];
                    const n = self.inner.read(space) catch |err| {
                        if (err == error.EndOfStream) {
                            self.eof = true;
                            break;
                        }
                        return err;
                    };
                    if (n == 0) {
                        self.eof = true;
                        break;
                    }
                    self.nchar += n;
                }

                if (self.nchar == 0) return 0;

                // Determine how many characters to decode
                var num_to_decode: usize = undefined;
                if (self.eof) {
                    num_to_decode = self.nchar;
                } else {
                    num_to_decode = (self.nchar / chars_per_block) * chars_per_block;
                }

                if (num_to_decode == 0) return 0;

                // Decode into output buffer
                const decoded_len = try Self.decode(self.allocator, self.char_buf[0..num_to_decode], &self.out_buf);
                self.out_start = 0;
                self.out_end = decoded_len;

                // Shift remaining characters
                const remaining = self.nchar - num_to_decode;
                if (remaining > 0) {
                    var i: usize = 0;
                    while (i < remaining) : (i += 1) {
                        self.char_buf[i] = self.char_buf[num_to_decode + i];
                    }
                }
                self.nchar = remaining;

                // Copy to dest
                const avail = self.out_end - self.out_start;
                const to_copy = @min(avail, dest.len);
                @memcpy(dest[0..to_copy], self.out_buf[self.out_start .. self.out_start + to_copy]);
                self.out_start += to_copy;
                return to_copy;
            }
        };
    };
}

/// Base62 encoding with 32-byte blocks (the saltpack default).
pub const base62 = Encoding(
    "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    32,
){};

// ========== Tests ==========

test "encode single zero byte" {
    const allocator = testing.allocator;
    const Base62 = Encoding("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", 32);
    var out: [2]u8 = undefined;
    const n = try Base62.encodeBlock(allocator, &[_]u8{0x00}, &out);
    try testing.expectEqual(@as(usize, 2), n);
    try testing.expectEqualSlices(u8, "00", out[0..n]);
}

test "encode single 0xff byte" {
    const allocator = testing.allocator;
    const Base62 = Encoding("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", 32);
    var out: [2]u8 = undefined;
    const n = try Base62.encodeBlock(allocator, &[_]u8{0xff}, &out);
    try testing.expectEqual(@as(usize, 2), n);
    // 255 = 4*62 + 7 => digits [4, 7] => chars "47"
    try testing.expectEqualSlices(u8, "47", out[0..n]);
}

test "encode 32 zero bytes" {
    const allocator = testing.allocator;
    const Base62 = Encoding("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", 32);
    var out: [43]u8 = undefined;
    const n = try Base62.encodeBlock(allocator, &([_]u8{0x00} ** 32), &out);
    try testing.expectEqual(@as(usize, 43), n);
    try testing.expectEqualSlices(u8, &([_]u8{'0'} ** 43), out[0..n]);
}

test "decode reverses encode" {
    const allocator = testing.allocator;
    const Base62 = Encoding("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", 32);

    const test_inputs = [_][]const u8{
        &[_]u8{0x00},
        &[_]u8{0xff},
        &[_]u8{ 0x01, 0x02, 0x03 },
        &[_]u8{ 0xDE, 0xAD, 0xBE, 0xEF },
        &[_]u8{0x00} ** 32,
        &[_]u8{0xFF} ** 32,
    };

    for (test_inputs) |input| {
        const enc_len = Base62.encodedLen(input.len);
        var encoded: [128]u8 = undefined;
        const en = try Base62.encodeBlock(allocator, input, &encoded);
        try testing.expectEqual(enc_len, en);

        const dec_len = Base62.decodedLen(en);
        try testing.expectEqual(input.len, dec_len);

        var decoded: [128]u8 = undefined;
        const dn = try Base62.decodeBlock(allocator, encoded[0..en], &decoded);
        try testing.expectEqual(input.len, dn);
        try testing.expectEqualSlices(u8, input, decoded[0..dn]);
    }
}

test "decode rejects overflow" {
    const allocator = testing.allocator;
    const Base62 = Encoding("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", 32);

    // For 1-byte decode, max value is 255.
    // "zz" = 61*62+61 = 3843 > 255 => overflow
    var out: [128]u8 = undefined;
    const result = Base62.decodeBlock(allocator, "zz", &out);
    try testing.expectError(Error.Overflow, result);
}

test "decode rejects invalid encoding length" {
    const allocator = testing.allocator;
    const Base62 = Encoding("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", 32);

    // 4 chars: decodedLen(4)=2, decodedLen(3)=2, so 4 is non-minimal
    var out: [128]u8 = undefined;
    const result = Base62.decodeBlock(allocator, "0000", &out);
    try testing.expectError(Error.InvalidEncodingLength, result);
}

test "full block round-trip" {
    const allocator = testing.allocator;
    const Base62 = Encoding("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", 32);

    var input: [32]u8 = undefined;
    for (&input, 0..) |*b, i| {
        b.* = @truncate(i * 7 + 13);
    }

    var encoded: [43]u8 = undefined;
    const en = try Base62.encodeBlock(allocator, &input, &encoded);
    try testing.expectEqual(@as(usize, 43), en);

    var decoded: [32]u8 = undefined;
    const dn = try Base62.decodeBlock(allocator, &encoded, &decoded);
    try testing.expectEqual(@as(usize, 32), dn);
    try testing.expectEqualSlices(u8, &input, &decoded);
}

test "short block round-trip" {
    const allocator = testing.allocator;
    const Base62 = Encoding("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", 32);

    for (1..32) |len| {
        const enc_len = Base62.encodedLen(len);
        if (!Base62.isValidEncodingLength(enc_len)) continue;

        var input: [31]u8 = undefined;
        for (input[0..len], 0..) |*b, i| {
            b.* = @truncate(i * 3 + 5);
        }

        var encoded: [128]u8 = undefined;
        const en = try Base62.encodeBlock(allocator, input[0..len], &encoded);
        try testing.expectEqual(enc_len, en);

        var decoded: [128]u8 = undefined;
        const dn = try Base62.decodeBlock(allocator, encoded[0..en], &decoded);
        try testing.expectEqual(len, dn);
        try testing.expectEqualSlices(u8, input[0..len], decoded[0..dn]);
    }
}

test "multi-block encode and decode" {
    const allocator = testing.allocator;
    const Base62 = Encoding("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", 32);

    var input: [64]u8 = undefined;
    for (&input, 0..) |*b, i| {
        b.* = @truncate(i * 11 + 3);
    }

    const enc_len = Base62.encodedLen(64);
    try testing.expectEqual(@as(usize, 86), enc_len);

    var encoded: [86]u8 = undefined;
    const en = try Base62.encode(allocator, &input, &encoded);
    try testing.expectEqual(@as(usize, 86), en);

    var decoded: [64]u8 = undefined;
    const dn = try Base62.decode(allocator, &encoded, &decoded);
    try testing.expectEqual(@as(usize, 64), dn);
    try testing.expectEqualSlices(u8, &input, &decoded);
}

test "streaming encoder round-trip" {
    const allocator = testing.allocator;
    const Base62 = Encoding("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", 32);

    // Prepare input data: 70 bytes (2 full blocks + 6 bytes)
    var input: [70]u8 = undefined;
    for (&input, 0..) |*b, i| {
        b.* = @truncate(i * 17 + 1);
    }

    // Use a managed ArrayList for collecting output
    var list = std.array_list.AlignedManaged(u8, null).init(allocator);
    defer list.deinit();

    var enc = Base62.Encoder.init(allocator, list.writer().any());

    // Write in chunks of varying sizes
    var written: usize = 0;
    const chunk_sizes = [_]usize{ 10, 20, 15, 25 };
    for (chunk_sizes) |chunk_size| {
        const end = @min(written + chunk_size, input.len);
        const n = try enc.write(input[written..end]);
        written += n;
    }
    try enc.finish();

    // Encode with block encoder for comparison
    const expected_enc_len = Base62.encodedLen(input.len);
    var expected_encoded: [256]u8 = undefined;
    const en = try Base62.encode(allocator, &input, &expected_encoded);
    try testing.expectEqual(expected_enc_len, en);

    try testing.expectEqualSlices(u8, expected_encoded[0..en], list.items);
}

test "streaming decoder round-trip" {
    const allocator = testing.allocator;
    const Base62 = Encoding("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", 32);

    // Prepare input data
    var input: [70]u8 = undefined;
    for (&input, 0..) |*b, i| {
        b.* = @truncate(i * 17 + 1);
    }

    // Encode the data first
    const enc_len = Base62.encodedLen(input.len);
    var encoded: [256]u8 = undefined;
    const en = try Base62.encode(allocator, &input, &encoded);
    try testing.expectEqual(enc_len, en);

    // Now decode with streaming decoder
    var fbs = std.io.fixedBufferStream(encoded[0..en]);
    var dec = Base62.Decoder.init(allocator, fbs.reader().any());

    var decoded: [256]u8 = undefined;
    var total_read: usize = 0;
    while (true) {
        const n = try dec.read(decoded[total_read..]);
        if (n == 0) break;
        total_read += n;
    }

    try testing.expectEqual(input.len, total_read);
    try testing.expectEqualSlices(u8, &input, decoded[0..total_read]);
}

test "encodedLen and decodedLen" {
    const Base62 = Encoding("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", 32);

    try testing.expectEqual(@as(usize, 43), Base62.encodedLen(32));
    try testing.expectEqual(@as(usize, 32), Base62.decodedLen(43));
    try testing.expectEqual(@as(usize, 2), Base62.encodedLen(1));
    try testing.expectEqual(@as(usize, 1), Base62.decodedLen(2));
    try testing.expectEqual(@as(usize, 0), Base62.encodedLen(0));
    try testing.expectEqual(@as(usize, 0), Base62.decodedLen(0));
    try testing.expectEqual(@as(usize, 86), Base62.encodedLen(64));
    try testing.expectEqual(@as(usize, 64), Base62.decodedLen(86));
}

test "isValidEncodingLength" {
    const Base62 = Encoding("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", 32);

    try testing.expect(Base62.isValidEncodingLength(2));
    try testing.expect(Base62.isValidEncodingLength(3));
    try testing.expect(Base62.isValidEncodingLength(7));
    try testing.expect(Base62.isValidEncodingLength(11));
    try testing.expect(Base62.isValidEncodingLength(43));
    try testing.expect(!Base62.isValidEncodingLength(4));
}

test "decode rejects invalid character" {
    const allocator = testing.allocator;
    const Base62 = Encoding("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", 32);

    var out: [128]u8 = undefined;
    const result = Base62.decodeBlock(allocator, "0!", &out);
    try testing.expectError(Error.InvalidCharacter, result);
}

test "encodeBlock performs zero heap allocations" {
    // Use testing.failing_allocator which fails on any allocation attempt.
    // This proves our encode path is fully stack-allocated.
    const Base62 = Encoding("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", 32);
    const no_alloc = std.testing.failing_allocator;

    // Full block (32 bytes)
    var input: [32]u8 = undefined;
    for (&input, 0..) |*b, i| {
        b.* = @truncate(i * 7 + 13);
    }
    var encoded: [43]u8 = undefined;
    const n = try Base62.encodeBlock(no_alloc, &input, &encoded);
    try testing.expectEqual(@as(usize, 43), n);

    // Short block (1 byte)
    var short_out: [2]u8 = undefined;
    const n2 = try Base62.encodeBlock(no_alloc, &[_]u8{0xff}, &short_out);
    try testing.expectEqual(@as(usize, 2), n2);

    // Zero byte
    var zero_out: [2]u8 = undefined;
    const n3 = try Base62.encodeBlock(no_alloc, &[_]u8{0x00}, &zero_out);
    try testing.expectEqual(@as(usize, 2), n3);
}

test "decodeBlock performs zero heap allocations" {
    // Use testing.failing_allocator which fails on any allocation attempt.
    // This proves our decode path is fully stack-allocated.
    const Base62 = Encoding("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", 32);
    const no_alloc = std.testing.failing_allocator;

    // First encode with testing.allocator, then decode with no allocator
    const alloc = testing.allocator;

    // Full block round-trip
    var input: [32]u8 = undefined;
    for (&input, 0..) |*b, i| {
        b.* = @truncate(i * 7 + 13);
    }
    var encoded: [43]u8 = undefined;
    _ = try Base62.encodeBlock(alloc, &input, &encoded);

    var decoded: [32]u8 = undefined;
    const dn = try Base62.decodeBlock(no_alloc, &encoded, &decoded);
    try testing.expectEqual(@as(usize, 32), dn);
    try testing.expectEqualSlices(u8, &input, &decoded);

    // Short block
    var short_enc: [2]u8 = undefined;
    _ = try Base62.encodeBlock(alloc, &[_]u8{0xff}, &short_enc);
    var short_dec: [1]u8 = undefined;
    const dn2 = try Base62.decodeBlock(no_alloc, &short_enc, &short_dec);
    try testing.expectEqual(@as(usize, 1), dn2);
    try testing.expectEqual(@as(u8, 0xff), short_dec[0]);
}

test "multi-block encode performs zero heap allocations" {
    const Base62 = Encoding("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", 32);
    const no_alloc = std.testing.failing_allocator;

    // 64 bytes = 2 full blocks
    var input: [64]u8 = undefined;
    for (&input, 0..) |*b, i| {
        b.* = @truncate(i * 11 + 3);
    }

    var encoded: [86]u8 = undefined;
    const en = try Base62.encode(no_alloc, &input, &encoded);
    try testing.expectEqual(@as(usize, 86), en);

    var decoded: [64]u8 = undefined;
    const dn = try Base62.decode(no_alloc, &encoded, &decoded);
    try testing.expectEqual(@as(usize, 64), dn);
    try testing.expectEqualSlices(u8, &input, &decoded);
}

test "encode/decode all-0xff full block" {
    const Base62 = Encoding("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", 32);
    const no_alloc = std.testing.failing_allocator;

    const input = [_]u8{0xFF} ** 32;
    var encoded: [43]u8 = undefined;
    const en = try Base62.encodeBlock(no_alloc, &input, &encoded);
    try testing.expectEqual(@as(usize, 43), en);

    var decoded: [32]u8 = undefined;
    const dn = try Base62.decodeBlock(no_alloc, encoded[0..en], &decoded);
    try testing.expectEqual(@as(usize, 32), dn);
    try testing.expectEqualSlices(u8, &input, &decoded);
}

test "encode/decode all-0x00 full block" {
    const Base62 = Encoding("0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz", 32);
    const no_alloc = std.testing.failing_allocator;

    const input = [_]u8{0x00} ** 32;
    var encoded: [43]u8 = undefined;
    const en = try Base62.encodeBlock(no_alloc, &input, &encoded);
    try testing.expectEqual(@as(usize, 43), en);
    try testing.expectEqualSlices(u8, &([_]u8{'0'} ** 43), &encoded);

    var decoded: [32]u8 = undefined;
    const dn = try Base62.decodeBlock(no_alloc, &encoded, &decoded);
    try testing.expectEqual(@as(usize, 32), dn);
    try testing.expectEqualSlices(u8, &input, &decoded);
}
