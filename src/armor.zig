//! Armor framing and Base62 encode/decode for saltpack.
//!
//! Implements the saltpack ASCII armor format (WP8), which wraps binary
//! messages in a human-readable framing with Base62-encoded payloads.
//!
//! Format:
//!   BEGIN [BRAND] SALTPACK {TYPE}. <base62 payload>. END [BRAND] SALTPACK {TYPE}.
//!
//! The payload is formatted with a space every 15 characters ("words")
//! and a newline every 200 words.

const std = @import("std");
const mem = std.mem;
const Allocator = std.mem.Allocator;
const testing = std.testing;
const basex = @import("basex.zig");
const types = @import("types.zig");

/// The Base62 encoding type, used for accessing type-level functions.
const Base62 = @TypeOf(basex.base62);

/// Errors that can occur during armor encoding/decoding.
pub const Error = error{
    /// The frame (header or footer) is malformed.
    BadFrame,
    /// The header and footer do not match.
    FrameMismatch,
    /// The armored message is truncated or missing a required section.
    Truncated,
};

/// Maximum length of a frame (header or footer), in characters.
const max_frame_length: usize = 512;

/// Maximum length of a brand string.
const max_brand_length: usize = 128;

/// Number of characters per "word" in the formatted payload.
const chars_per_word: usize = 15;

/// Number of words per line in the formatted payload.
const words_per_line: usize = 200;

/// Maximum number of words in a frame (BEGIN/END + optional brand + SALTPACK + type1 + type2).
const max_frame_words: usize = 5;

/// Parsed frame information.
pub const Frame = struct {
    message_type: types.MessageType,
    brand: ?[]const u8, // null if no brand
};

/// Get the armor type string for a message type.
/// Returns the uppercase suffix used in header/footer frames.
pub fn messageTypeString(msg_type: types.MessageType) []const u8 {
    return switch (msg_type) {
        .encryption => types.encryption_armor_string,
        .attached_signature => types.signed_armor_string,
        .detached_signature => types.detached_signature_armor_string,
        .signcryption => types.encryption_armor_string,
    };
}

/// Format the header frame string.
/// Returns an allocated string like "BEGIN SALTPACK ENCRYPTED MESSAGE"
/// or "BEGIN MYAPP SALTPACK ENCRYPTED MESSAGE" with a brand.
pub fn formatHeader(allocator: Allocator, message_type: types.MessageType, brand: ?[]const u8) ![]u8 {
    return formatFrame(allocator, "BEGIN", message_type, brand);
}

/// Format the footer frame string.
/// Returns an allocated string like "END SALTPACK ENCRYPTED MESSAGE"
/// or "END MYAPP SALTPACK ENCRYPTED MESSAGE" with a brand.
pub fn formatFooter(allocator: Allocator, message_type: types.MessageType, brand: ?[]const u8) ![]u8 {
    return formatFrame(allocator, "END", message_type, brand);
}

/// Internal: format a frame with the given marker ("BEGIN" or "END").
fn formatFrame(allocator: Allocator, marker: []const u8, message_type: types.MessageType, brand: ?[]const u8) ![]u8 {
    const type_str = messageTypeString(message_type);
    if (type_str.len == 0) return Error.BadFrame;

    // Reject brands that exceed the maximum allowed length.
    if (brand) |b| {
        if (b.len > max_brand_length) return Error.BadFrame;
    }

    const format_upper = "SALTPACK";

    // Calculate total length
    // marker + " " + [brand + " "] + "SALTPACK" + " " + type_str
    var total_len: usize = marker.len + 1 + format_upper.len + 1 + type_str.len;
    if (brand) |b| {
        total_len += b.len + 1; // brand + " "
    }

    const result = try allocator.alloc(u8, total_len);
    var pos: usize = 0;

    @memcpy(result[pos .. pos + marker.len], marker);
    pos += marker.len;

    result[pos] = ' ';
    pos += 1;

    if (brand) |b| {
        @memcpy(result[pos .. pos + b.len], b);
        pos += b.len;
        result[pos] = ' ';
        pos += 1;
    }

    @memcpy(result[pos .. pos + format_upper.len], format_upper);
    pos += format_upper.len;

    result[pos] = ' ';
    pos += 1;

    @memcpy(result[pos .. pos + type_str.len], type_str);
    pos += type_str.len;

    return result;
}

/// Parse a frame string, extracting the message type and optional brand.
///
/// `frame_str` is the text between periods (whitespace-trimmed).
/// `expect_begin` controls whether we expect "BEGIN" (true) or "END" (false).
pub fn parseFrame(frame_str: []const u8, expect_begin: bool) !Frame {
    if (frame_str.len > max_frame_length) {
        return Error.BadFrame;
    }

    // Split the frame string into words, skipping whitespace characters.
    // Words are slices into the original frame_str, so they remain valid
    // as long as frame_str is valid.
    var word_buf: [max_frame_words][]const u8 = undefined;
    var word_count: usize = 0;

    var i: usize = 0;
    while (i < frame_str.len) {
        // Skip whitespace.
        if (isWhitespaceChar(frame_str[i])) {
            i += 1;
            continue;
        }
        // Start of a word.
        const word_start = i;
        while (i < frame_str.len and !isWhitespaceChar(frame_str[i])) {
            i += 1;
        }
        if (word_count >= max_frame_words) {
            return Error.BadFrame;
        }
        word_buf[word_count] = frame_str[word_start..i];
        word_count += 1;
    }

    const w = word_buf[0..word_count];

    // Must be 4 words (no brand) or 5 words (with brand).
    // e.g. "BEGIN SALTPACK ENCRYPTED MESSAGE" (4)
    // or   "BEGIN MYAPP SALTPACK ENCRYPTED MESSAGE" (5)
    if (w.len != 4 and w.len != 5) {
        return Error.BadFrame;
    }

    // Check marker (first word).
    const expected_marker: []const u8 = if (expect_begin) "BEGIN" else "END";
    if (!mem.eql(u8, w[0], expected_marker)) {
        return Error.BadFrame;
    }

    // The last two words form the message type suffix.
    const type_suffix_parts = [2][]const u8{ w[w.len - 2], w[w.len - 1] };

    // The word before the type suffix must be "SALTPACK".
    const saltpack_idx = w.len - 3;
    if (!mem.eql(u8, w[saltpack_idx], "SALTPACK")) {
        return Error.BadFrame;
    }

    // Match the type suffix to a MessageType.
    const msg_type = try matchMessageType(type_suffix_parts);

    // Extract brand if present (5 words means word[1] is the brand).
    var brand: ?[]const u8 = null;
    if (w.len == 5) {
        const b = w[1];
        if (b.len > max_brand_length) {
            return Error.BadFrame;
        }
        // Validate brand is alphanumeric.
        for (b) |ch| {
            if (!std.ascii.isAlphanumeric(ch)) {
                return Error.BadFrame;
            }
        }
        brand = b;
    }

    return Frame{
        .message_type = msg_type,
        .brand = brand,
    };
}

/// Match a two-word type suffix to a MessageType.
fn matchMessageType(parts: [2][]const u8) !types.MessageType {
    // "ENCRYPTED MESSAGE"
    if (mem.eql(u8, parts[0], "ENCRYPTED") and mem.eql(u8, parts[1], "MESSAGE")) {
        return .encryption;
    }
    // "SIGNED MESSAGE"
    if (mem.eql(u8, parts[0], "SIGNED") and mem.eql(u8, parts[1], "MESSAGE")) {
        return .attached_signature;
    }
    // "DETACHED SIGNATURE"
    if (mem.eql(u8, parts[0], "DETACHED") and mem.eql(u8, parts[1], "SIGNATURE")) {
        return .detached_signature;
    }
    return Error.BadFrame;
}

/// Check if a character is in our whitespace set.
fn isWhitespaceChar(ch: u8) bool {
    return switch (ch) {
        '\t', '\n', '\r', ' ', '>' => true,
        else => false,
    };
}

/// Encode binary data into armored format.
///
/// Produces the full armored string:
///   "BEGIN [BRAND] SALTPACK {TYPE}. <formatted base62 payload>. END [BRAND] SALTPACK {TYPE}."
pub fn encode(
    allocator: Allocator,
    data: []const u8,
    message_type: types.MessageType,
    brand: ?[]const u8,
) ![]u8 {
    // 1. Generate header and footer frames.
    const hdr = try formatHeader(allocator, message_type, brand);
    defer allocator.free(hdr);
    const ftr = try formatFooter(allocator, message_type, brand);
    defer allocator.free(ftr);

    // 2. Base62 encode the binary data.
    const enc_len = Base62.encodedLen(data.len);
    var encoded_buf: []u8 = undefined;
    var actual_enc_len: usize = 0;

    if (enc_len > 0) {
        encoded_buf = try allocator.alloc(u8, enc_len);
        actual_enc_len = try Base62.encode(allocator, data, encoded_buf);
    }
    defer if (enc_len > 0) allocator.free(encoded_buf);

    const encoded_slice = if (enc_len > 0) encoded_buf[0..actual_enc_len] else &[_]u8{};

    // 3. Format encoded data with word spacing.
    const formatted = try formatPayload(allocator, encoded_slice);
    defer allocator.free(formatted);

    // 4. Concatenate: header + ". " + formatted_payload + ". " + footer + "."
    const total_len = hdr.len + 2 + formatted.len + 2 + ftr.len + 1;
    const result = try allocator.alloc(u8, total_len);
    var pos: usize = 0;

    @memcpy(result[pos .. pos + hdr.len], hdr);
    pos += hdr.len;

    result[pos] = '.';
    pos += 1;
    result[pos] = ' ';
    pos += 1;

    @memcpy(result[pos .. pos + formatted.len], formatted);
    pos += formatted.len;

    result[pos] = '.';
    pos += 1;
    result[pos] = ' ';
    pos += 1;

    @memcpy(result[pos .. pos + ftr.len], ftr);
    pos += ftr.len;

    result[pos] = '.';
    pos += 1;

    return result;
}

/// Format the base62-encoded payload with word and line spacing.
///
/// Inserts a space every `chars_per_word` (15) characters and
/// a newline every `words_per_line` (200) words.
fn formatPayload(allocator: Allocator, encoded: []const u8) ![]u8 {
    if (encoded.len == 0) {
        return try allocator.alloc(u8, 0);
    }

    // Calculate the number of separators needed.
    // A separator is inserted after every chars_per_word characters, except the last chunk.
    const num_full_words = encoded.len / chars_per_word;
    const has_remainder = (encoded.len % chars_per_word) != 0;
    const num_separators = if (has_remainder) num_full_words else if (num_full_words > 0) num_full_words - 1 else @as(usize, 0);

    const total_len = encoded.len + num_separators;
    const result = try allocator.alloc(u8, total_len);
    var out_pos: usize = 0;
    var in_pos: usize = 0;
    var word_count: usize = 0;

    while (in_pos < encoded.len) {
        const chunk_end = @min(in_pos + chars_per_word, encoded.len);
        const chunk_len = chunk_end - in_pos;

        @memcpy(result[out_pos .. out_pos + chunk_len], encoded[in_pos..chunk_end]);
        out_pos += chunk_len;
        in_pos = chunk_end;
        word_count += 1;

        // Insert separator after this word, unless it's the last chunk.
        if (in_pos < encoded.len) {
            if (word_count % words_per_line == 0) {
                result[out_pos] = '\n';
            } else {
                result[out_pos] = ' ';
            }
            out_pos += 1;
        }
    }

    // If we allocated more than we used, realloc to exact size.
    if (out_pos < total_len) {
        return try allocator.realloc(result, out_pos);
    }
    return result;
}

/// Decode armored format back to binary data.
///
/// Returns the decoded binary data and the parsed frame info.
/// The caller owns the returned data and must free it with the same allocator.
pub fn decode(
    allocator: Allocator,
    armored: []const u8,
) !struct { data: []u8, frame: Frame } {
    // 1. Find first '.' -> header frame text.
    const header_end = mem.indexOfScalar(u8, armored, '.') orelse return Error.Truncated;
    const header_text = armored[0..header_end];

    // 2. Parse header frame.
    const header_frame = try parseFrame(header_text, true);

    // 3. Find next '.' -> payload text.
    const after_header = header_end + 1;
    if (after_header >= armored.len) return Error.Truncated;
    const payload_end = mem.indexOfScalarPos(u8, armored, after_header, '.') orelse return Error.Truncated;
    const payload_text = armored[after_header..payload_end];

    // 4. Strip whitespace chars from payload.
    const stripped = try stripWhitespace(allocator, payload_text);
    defer allocator.free(stripped);

    // 5. Decode stripped payload with basex.base62.
    if (stripped.len == 0) {
        // Empty payload.
        // 6. Find next '.' -> footer frame text.
        const after_payload = payload_end + 1;
        if (after_payload >= armored.len) return Error.Truncated;
        const footer_end = mem.indexOfScalarPos(u8, armored, after_payload, '.') orelse return Error.Truncated;
        const footer_text = armored[after_payload..footer_end];

        // 7. Parse and validate footer matches header.
        const footer_frame = try parseFrame(footer_text, false);
        try validateFrameMatch(header_frame, footer_frame);

        return .{
            .data = try allocator.alloc(u8, 0),
            .frame = header_frame,
        };
    }

    const dec_len = Base62.decodedLen(stripped.len);
    var decoded_buf = try allocator.alloc(u8, dec_len);
    errdefer allocator.free(decoded_buf);

    const actual_dec_len = try Base62.decode(allocator, stripped, decoded_buf);

    // Resize to actual decoded length if needed.
    if (actual_dec_len < dec_len) {
        decoded_buf = try allocator.realloc(decoded_buf, actual_dec_len);
    }

    // 6. Find next '.' -> footer frame text.
    const after_payload = payload_end + 1;
    if (after_payload >= armored.len) return Error.Truncated;
    const footer_end = mem.indexOfScalarPos(u8, armored, after_payload, '.') orelse return Error.Truncated;
    const footer_text = armored[after_payload..footer_end];

    // 7. Parse and validate footer matches header.
    const footer_frame = try parseFrame(footer_text, false);
    try validateFrameMatch(header_frame, footer_frame);

    return .{
        .data = decoded_buf,
        .frame = header_frame,
    };
}

/// Validate that header and footer frames match.
fn validateFrameMatch(header_frame: Frame, footer_frame: Frame) !void {
    if (footer_frame.message_type != header_frame.message_type) {
        return Error.FrameMismatch;
    }

    const h_brand = header_frame.brand;
    const f_brand = footer_frame.brand;
    if (h_brand == null and f_brand != null) return Error.FrameMismatch;
    if (h_brand != null and f_brand == null) return Error.FrameMismatch;
    if (h_brand != null and f_brand != null) {
        if (!mem.eql(u8, h_brand.?, f_brand.?)) {
            return Error.FrameMismatch;
        }
    }
}

/// Strip all whitespace characters from the payload.
fn stripWhitespace(allocator: Allocator, input: []const u8) ![]u8 {
    var result = try allocator.alloc(u8, input.len);
    var pos: usize = 0;
    for (input) |ch| {
        if (!isWhitespaceChar(ch)) {
            result[pos] = ch;
            pos += 1;
        }
    }
    if (pos < input.len) {
        result = try allocator.realloc(result, pos);
    }
    return result;
}

// ========== Tests ==========

test "messageTypeString" {
    try testing.expectEqualStrings("ENCRYPTED MESSAGE", messageTypeString(.encryption));
    try testing.expectEqualStrings("SIGNED MESSAGE", messageTypeString(.attached_signature));
    try testing.expectEqualStrings("DETACHED SIGNATURE", messageTypeString(.detached_signature));
}

test "formatHeader no brand" {
    const allocator = testing.allocator;
    const result = try formatHeader(allocator, .encryption, null);
    defer allocator.free(result);
    try testing.expectEqualStrings("BEGIN SALTPACK ENCRYPTED MESSAGE", result);
}

test "formatHeader with brand" {
    const allocator = testing.allocator;
    const result = try formatHeader(allocator, .attached_signature, "MYAPP");
    defer allocator.free(result);
    try testing.expectEqualStrings("BEGIN MYAPP SALTPACK SIGNED MESSAGE", result);
}

test "formatFooter" {
    const allocator = testing.allocator;
    const result = try formatFooter(allocator, .encryption, null);
    defer allocator.free(result);
    try testing.expectEqualStrings("END SALTPACK ENCRYPTED MESSAGE", result);
}

test "parseFrame begin" {
    const frame = try parseFrame("BEGIN SALTPACK ENCRYPTED MESSAGE", true);
    try testing.expectEqual(types.MessageType.encryption, frame.message_type);
    try testing.expect(frame.brand == null);
}

test "parseFrame end" {
    const frame = try parseFrame("END SALTPACK ENCRYPTED MESSAGE", false);
    try testing.expectEqual(types.MessageType.encryption, frame.message_type);
    try testing.expect(frame.brand == null);
}

test "parseFrame with brand" {
    const frame = try parseFrame("BEGIN MYAPP SALTPACK SIGNED MESSAGE", true);
    try testing.expectEqual(types.MessageType.attached_signature, frame.message_type);
    try testing.expect(frame.brand != null);
    try testing.expectEqualStrings("MYAPP", frame.brand.?);
}

test "parseFrame detached signature" {
    const frame = try parseFrame("BEGIN SALTPACK DETACHED SIGNATURE", true);
    try testing.expectEqual(types.MessageType.detached_signature, frame.message_type);
    try testing.expect(frame.brand == null);
}

test "parseFrame rejects wrong marker" {
    const result = parseFrame("END SALTPACK ENCRYPTED MESSAGE", true);
    try testing.expectError(Error.BadFrame, result);
}

test "parseFrame rejects wrong word count" {
    const result = parseFrame("BEGIN SALTPACK", true);
    try testing.expectError(Error.BadFrame, result);
}

test "parseFrame tolerates extra whitespace in frame" {
    const frame = try parseFrame("  BEGIN  SALTPACK  ENCRYPTED  MESSAGE  ", true);
    try testing.expectEqual(types.MessageType.encryption, frame.message_type);
}

test "encode decode round-trip" {
    const allocator = testing.allocator;
    const input = "Hello, saltpack!";
    const armored = try encode(allocator, input, .encryption, null);
    defer allocator.free(armored);

    const result = try decode(allocator, armored);
    defer allocator.free(result.data);

    try testing.expectEqualStrings(input, result.data);
    try testing.expectEqual(types.MessageType.encryption, result.frame.message_type);
    try testing.expect(result.frame.brand == null);
}

test "encode decode with brand" {
    const allocator = testing.allocator;
    const input = "Branded message";
    const armored = try encode(allocator, input, .attached_signature, "KEYBASE");
    defer allocator.free(armored);

    const result = try decode(allocator, armored);
    defer allocator.free(result.data);

    try testing.expectEqualStrings(input, result.data);
    try testing.expectEqual(types.MessageType.attached_signature, result.frame.message_type);
    try testing.expect(result.frame.brand != null);
    try testing.expectEqualStrings("KEYBASE", result.frame.brand.?);
}

test "encode produces correct word spacing" {
    const allocator = testing.allocator;

    // Create input that produces enough base62 output to see spacing.
    // 32 bytes -> 43 base62 chars. That's 2 full words (30 chars) + 13 chars remainder.
    var input: [32]u8 = undefined;
    for (&input, 0..) |*b, i| {
        b.* = @truncate(i);
    }

    const armored = try encode(allocator, &input, .encryption, null);
    defer allocator.free(armored);

    // Extract the payload between the first and second periods.
    const first_dot = mem.indexOfScalar(u8, armored, '.').?;
    const second_dot = mem.indexOfScalarPos(u8, armored, first_dot + 1, '.').?;
    const payload = armored[first_dot + 2 .. second_dot]; // skip ". "

    // The payload should have spaces. Check that no run of non-space chars
    // exceeds chars_per_word (15).
    var run_len: usize = 0;
    for (payload) |ch| {
        if (ch == ' ' or ch == '\n') {
            try testing.expect(run_len <= chars_per_word);
            run_len = 0;
        } else {
            run_len += 1;
        }
    }
    // Last run should also be <= chars_per_word.
    try testing.expect(run_len <= chars_per_word);
}

test "decode tolerates extra whitespace" {
    const allocator = testing.allocator;
    const input = "test data";

    // First encode normally.
    const armored = try encode(allocator, input, .encryption, null);
    defer allocator.free(armored);

    // Now mangle the payload by inserting extra whitespace/tabs/newlines/>.
    const first_dot = mem.indexOfScalar(u8, armored, '.').?;
    const second_dot = mem.indexOfScalarPos(u8, armored, first_dot + 1, '.').?;

    // Build a modified armored string with extra whitespace in the payload.
    var mangled_buf: [4096]u8 = undefined;
    var mangled_len: usize = 0;

    // Header up to and including first dot.
    @memcpy(mangled_buf[mangled_len .. mangled_len + first_dot + 1], armored[0 .. first_dot + 1]);
    mangled_len += first_dot + 1;

    // Extra whitespace before payload.
    const extra_ws = " \t\n> ";
    @memcpy(mangled_buf[mangled_len .. mangled_len + extra_ws.len], extra_ws);
    mangled_len += extra_ws.len;

    // Payload characters with extra tabs inserted.
    const payload_start = first_dot + 2;
    for (armored[payload_start..second_dot]) |ch| {
        mangled_buf[mangled_len] = ch;
        mangled_len += 1;
        if (ch != ' ' and ch != '\n') {
            mangled_buf[mangled_len] = '\t';
            mangled_len += 1;
        }
    }

    // Rest from second dot onward.
    const rest = armored[second_dot..];
    @memcpy(mangled_buf[mangled_len .. mangled_len + rest.len], rest);
    mangled_len += rest.len;

    const result = try decode(allocator, mangled_buf[0..mangled_len]);
    defer allocator.free(result.data);

    try testing.expectEqualStrings(input, result.data);
}

test "decode rejects mismatched frames" {
    const allocator = testing.allocator;

    // Manually construct an armored string with mismatched header/footer types.
    const bad_armored = "BEGIN SALTPACK ENCRYPTED MESSAGE. 00. END SALTPACK SIGNED MESSAGE.";
    const result = decode(allocator, bad_armored);
    try testing.expectError(Error.FrameMismatch, result);
}

test "decode rejects mismatched brands" {
    const allocator = testing.allocator;

    const bad_armored = "BEGIN BRAND1 SALTPACK ENCRYPTED MESSAGE. 00. END BRAND2 SALTPACK ENCRYPTED MESSAGE.";
    const result = decode(allocator, bad_armored);
    try testing.expectError(Error.FrameMismatch, result);
}

test "all message types round-trip" {
    const allocator = testing.allocator;
    const input = "round-trip test data for all types";

    const message_types = [_]types.MessageType{
        .encryption,
        .attached_signature,
        .detached_signature,
    };

    for (message_types) |msg_type| {
        const armored = try encode(allocator, input, msg_type, null);
        defer allocator.free(armored);

        const result = try decode(allocator, armored);
        defer allocator.free(result.data);

        try testing.expectEqualStrings(input, result.data);
        try testing.expectEqual(msg_type, result.frame.message_type);
    }
}

test "all message types round-trip with brand" {
    const allocator = testing.allocator;
    const input = "round-trip test data with brand";

    const message_types = [_]types.MessageType{
        .encryption,
        .attached_signature,
        .detached_signature,
    };

    for (message_types) |msg_type| {
        const armored = try encode(allocator, input, msg_type, "TESTBRAND");
        defer allocator.free(armored);

        const result = try decode(allocator, armored);
        defer allocator.free(result.data);

        try testing.expectEqualStrings(input, result.data);
        try testing.expectEqual(msg_type, result.frame.message_type);
        try testing.expect(result.frame.brand != null);
        try testing.expectEqualStrings("TESTBRAND", result.frame.brand.?);
    }
}

test "encode decode empty data" {
    const allocator = testing.allocator;
    const input: []const u8 = "";

    const armored = try encode(allocator, input, .encryption, null);
    defer allocator.free(armored);

    const result = try decode(allocator, armored);
    defer allocator.free(result.data);

    try testing.expectEqual(@as(usize, 0), result.data.len);
}

test "encode decode large data" {
    const allocator = testing.allocator;

    // 256 bytes - multiple base62 blocks.
    var input: [256]u8 = undefined;
    for (&input, 0..) |*b, i| {
        b.* = @truncate(i *% 37 +% 13);
    }

    const armored = try encode(allocator, &input, .detached_signature, null);
    defer allocator.free(armored);

    const result = try decode(allocator, armored);
    defer allocator.free(result.data);

    try testing.expectEqualSlices(u8, &input, result.data);
}

test "decode rejects truncated input" {
    const allocator = testing.allocator;

    // Missing footer period.
    const truncated = "BEGIN SALTPACK ENCRYPTED MESSAGE. 00";
    const result = decode(allocator, truncated);
    try testing.expectError(Error.Truncated, result);
}

test "messageTypeString maps signcryption to ENCRYPTED MESSAGE" {
    // Per the Go reference, signcryption uses the same armor framing as encryption.
    try testing.expectEqualStrings("ENCRYPTED MESSAGE", messageTypeString(.signcryption));
}

test "signcryption encode decode round-trip uses encryption armor" {
    const allocator = testing.allocator;
    const input = "signcrypted data";
    const armored = try encode(allocator, input, .signcryption, null);
    defer allocator.free(armored);

    // The armor should use "ENCRYPTED MESSAGE" framing.
    try testing.expect(std.mem.indexOf(u8, armored, "BEGIN SALTPACK ENCRYPTED MESSAGE") != null);
    try testing.expect(std.mem.indexOf(u8, armored, "END SALTPACK ENCRYPTED MESSAGE") != null);

    // Decode should succeed (returns .encryption since the armor string is shared).
    const result = try decode(allocator, armored);
    defer allocator.free(result.data);

    try testing.expectEqualStrings(input, result.data);
    try testing.expectEqual(types.MessageType.encryption, result.frame.message_type);
}

test "signcryption encode decode with brand" {
    const allocator = testing.allocator;
    const input = "signcrypted with brand";
    const armored = try encode(allocator, input, .signcryption, "MYAPP");
    defer allocator.free(armored);

    try testing.expect(std.mem.indexOf(u8, armored, "BEGIN MYAPP SALTPACK ENCRYPTED MESSAGE") != null);
    try testing.expect(std.mem.indexOf(u8, armored, "END MYAPP SALTPACK ENCRYPTED MESSAGE") != null);

    const result = try decode(allocator, armored);
    defer allocator.free(result.data);

    try testing.expectEqualStrings(input, result.data);
    try testing.expect(result.frame.brand != null);
    try testing.expectEqualStrings("MYAPP", result.frame.brand.?);
}

test "formatFrame rejects brand exceeding max_brand_length" {
    const allocator = testing.allocator;

    // Create a brand that is exactly max_brand_length + 1 (129 bytes).
    const long_brand = "A" ** 129;
    const result = formatHeader(allocator, .encryption, long_brand);
    try testing.expectError(Error.BadFrame, result);
}

test "formatFrame accepts brand at exactly max_brand_length" {
    const allocator = testing.allocator;

    // Create a brand that is exactly max_brand_length (128 bytes).
    const max_brand = "A" ** 128;
    const result = try formatHeader(allocator, .encryption, max_brand);
    defer allocator.free(result);

    // Should contain the brand in the output.
    try testing.expect(std.mem.indexOf(u8, result, max_brand) != null);
}

test "encode rejects oversized brand" {
    const allocator = testing.allocator;

    const long_brand = "B" ** 129;
    const result = encode(allocator, "data", .encryption, long_brand);
    try testing.expectError(Error.BadFrame, result);
}
