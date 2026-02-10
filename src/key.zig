//! Key types and KeyRing interfaces for saltpack.
//!
//! Zig port of the Go saltpack library's key.go interfaces.
//! Uses concrete structs with Zig's comptime duck-typing pattern
//! instead of Go's runtime interfaces.

const std = @import("std");
const crypto = std.crypto;
const sp_errors = @import("errors.zig");

// ---------------------------------------------------------------------------
// BoxPublicKey
// ---------------------------------------------------------------------------

/// A NaCl Box public key (Curve25519, 32 bytes).
pub const BoxPublicKey = struct {
    pub const key_length = 32;

    bytes: [key_length]u8,
    hide_identity: bool = false,

    /// Returns the key ID for this public key. By default, the KID is
    /// simply the raw public key bytes.
    pub fn toKid(self: BoxPublicKey) [key_length]u8 {
        return self.bytes;
    }

    /// Returns the raw key bytes as a slice.
    pub fn toBytes(self: *const BoxPublicKey) *const [key_length]u8 {
        return &self.bytes;
    }

    /// Returns true if two public keys are equal, using constant-time comparison.
    pub fn eql(self: BoxPublicKey, other: BoxPublicKey) bool {
        return std.crypto.timing_safe.eql([key_length]u8, self.bytes, other.bytes);
    }

    /// Creates a BoxPublicKey from raw bytes.
    /// Returns `BadPublicKey` if the key is all-zero (a low-order point).
    pub fn fromBytes(bytes: [key_length]u8) !BoxPublicKey {
        const zero = [_]u8{0} ** key_length;
        if (std.crypto.timing_safe.eql([key_length]u8, bytes, zero)) {
            return sp_errors.Error.BadPublicKey;
        }
        return .{ .bytes = bytes };
    }

    /// Creates a BoxPublicKey from a slice. Returns error if the slice
    /// is not exactly 32 bytes, or if the key is all-zero (a low-order point).
    pub fn fromSlice(slice: []const u8) !BoxPublicKey {
        if (slice.len != key_length) {
            return error.BadBoxKey;
        }
        const zero = [_]u8{0} ** key_length;
        if (std.crypto.timing_safe.eql([key_length]u8, slice[0..key_length].*, zero)) {
            return sp_errors.Error.BadPublicKey;
        }
        return .{ .bytes = slice[0..key_length].* };
    }
};

// ---------------------------------------------------------------------------
// BoxSecretKey
// ---------------------------------------------------------------------------

/// A NaCl Box secret key (Curve25519, 32 bytes).
pub const BoxSecretKey = struct {
    pub const key_length = 32;

    bytes: [key_length]u8,
    public_key: BoxPublicKey,

    /// Returns the public key associated with this secret key.
    pub fn getPublicKey(self: BoxSecretKey) BoxPublicKey {
        return self.public_key;
    }

    /// Creates a BoxSecretKey from raw bytes and the corresponding public key.
    /// Returns `BadSecretKey` if the secret key bytes are all-zero.
    pub fn fromBytes(secret_bytes: [key_length]u8, public_key: BoxPublicKey) !BoxSecretKey {
        const zero = [_]u8{0} ** key_length;
        if (std.crypto.timing_safe.eql([key_length]u8, secret_bytes, zero)) {
            return sp_errors.Error.BadSecretKey;
        }
        return .{
            .bytes = secret_bytes,
            .public_key = public_key,
        };
    }
};

// ---------------------------------------------------------------------------
// BoxKeyPair
// ---------------------------------------------------------------------------

/// A NaCl Box key pair (Curve25519).
pub const BoxKeyPair = struct {
    public_key: BoxPublicKey,
    secret_key: BoxSecretKey,

    /// Generates a new random Box key pair using the system CSPRNG.
    pub fn generate() BoxKeyPair {
        const nacl_kp = crypto.nacl.Box.KeyPair.generate();
        const pk = BoxPublicKey{ .bytes = nacl_kp.public_key };
        const sk = BoxSecretKey{
            .bytes = nacl_kp.secret_key,
            .public_key = pk,
        };
        return .{
            .public_key = pk,
            .secret_key = sk,
        };
    }

    /// Securely zeros the secret key bytes. Call this when the key pair
    /// is no longer needed to limit the window of exposure.
    pub fn wipe(self: *BoxKeyPair) void {
        std.crypto.secureZero(u8, &self.secret_key.bytes);
    }

    /// Generates a key pair deterministically from a seed.
    pub fn fromSeed(seed: [32]u8) !BoxKeyPair {
        const nacl_kp = crypto.nacl.Box.KeyPair.generateDeterministic(seed) catch {
            return error.BadBoxKey;
        };
        const pk = BoxPublicKey{ .bytes = nacl_kp.public_key };
        const sk = BoxSecretKey{
            .bytes = nacl_kp.secret_key,
            .public_key = pk,
        };
        return .{
            .public_key = pk,
            .secret_key = sk,
        };
    }
};

// ---------------------------------------------------------------------------
// SigningPublicKey
// ---------------------------------------------------------------------------

/// An Ed25519 public key (32 bytes).
pub const SigningPublicKey = struct {
    pub const key_length = 32;

    bytes: [key_length]u8,

    /// Returns the key ID (the raw public key bytes).
    pub fn toKid(self: SigningPublicKey) [key_length]u8 {
        return self.bytes;
    }

    /// Returns true if two signing public keys are equal, using constant-time comparison.
    pub fn eql(self: SigningPublicKey, other: SigningPublicKey) bool {
        return std.crypto.timing_safe.eql([key_length]u8, self.bytes, other.bytes);
    }

    /// Creates a SigningPublicKey from raw bytes.
    /// Returns `BadPublicKey` if the key is all-zero.
    pub fn fromBytes(bytes: [key_length]u8) !SigningPublicKey {
        const zero = [_]u8{0} ** key_length;
        if (std.mem.eql(u8, &bytes, &zero)) {
            return sp_errors.Error.BadPublicKey;
        }
        return .{ .bytes = bytes };
    }

    /// Verify that a signature is valid for the given message.
    pub fn verify(self: SigningPublicKey, message: []const u8, signature_bytes: [64]u8) !void {
        const ed_pk = crypto.sign.Ed25519.PublicKey.fromBytes(self.bytes) catch {
            return error.BadSignature;
        };
        const sig = crypto.sign.Ed25519.Signature.fromBytes(signature_bytes);
        sig.verify(message, ed_pk) catch {
            return error.BadSignature;
        };
    }
};

// ---------------------------------------------------------------------------
// SigningSecretKey
// ---------------------------------------------------------------------------

/// An Ed25519 secret key (64 bytes: 32-byte seed + 32-byte public key).
pub const SigningSecretKey = struct {
    pub const key_length = 64;

    bytes: [key_length]u8,
    public_key: SigningPublicKey,

    /// Returns the public key associated with this secret key.
    pub fn getPublicKey(self: SigningSecretKey) SigningPublicKey {
        return self.public_key;
    }

    /// Sign a message with this secret key. Returns a 64-byte signature.
    pub fn sign(self: SigningSecretKey, message: []const u8) ![64]u8 {
        const sk = crypto.sign.Ed25519.SecretKey.fromBytes(self.bytes) catch {
            return error.BadSignature;
        };
        const kp = crypto.sign.Ed25519.KeyPair{
            .public_key = crypto.sign.Ed25519.PublicKey.fromBytes(self.public_key.bytes) catch {
                return error.BadSignature;
            },
            .secret_key = sk,
        };
        const sig = kp.sign(message, null) catch {
            return error.BadSignature;
        };
        return sig.toBytes();
    }
};

// ---------------------------------------------------------------------------
// SigningKeyPair
// ---------------------------------------------------------------------------

/// An Ed25519 key pair.
pub const SigningKeyPair = struct {
    public_key: SigningPublicKey,
    secret_key: SigningSecretKey,

    /// Generates a new random Ed25519 key pair using the system CSPRNG.
    pub fn generate() SigningKeyPair {
        const ed_kp = crypto.sign.Ed25519.KeyPair.generate();
        const pk = SigningPublicKey{ .bytes = ed_kp.public_key.bytes };
        const sk = SigningSecretKey{
            .bytes = ed_kp.secret_key.bytes,
            .public_key = pk,
        };
        return .{
            .public_key = pk,
            .secret_key = sk,
        };
    }

    /// Securely zeros the secret key bytes. Call this when the key pair
    /// is no longer needed to limit the window of exposure.
    pub fn wipe(self: *SigningKeyPair) void {
        std.crypto.secureZero(u8, &self.secret_key.bytes);
    }

    /// Generates a key pair deterministically from a 32-byte seed.
    pub fn fromSeed(seed: [32]u8) !SigningKeyPair {
        const ed_kp = crypto.sign.Ed25519.KeyPair.generateDeterministic(seed) catch {
            return error.BadSignature;
        };
        const pk = SigningPublicKey{ .bytes = ed_kp.public_key.bytes };
        const sk = SigningSecretKey{
            .bytes = ed_kp.secret_key.bytes,
            .public_key = pk,
        };
        return .{
            .public_key = pk,
            .secret_key = sk,
        };
    }
};

// ---------------------------------------------------------------------------
// KeyRing comptime interface validation
// ---------------------------------------------------------------------------

/// Validates at comptime that a type T satisfies the KeyRing interface.
/// The KeyRing interface requires the following methods:
///   - lookupBoxSecretKey(kids: []const []const u8) ?struct { index: usize, key: BoxSecretKey }
///   - lookupBoxPublicKey(kid: []const u8) ?BoxPublicKey
///   - getAllBoxSecretKeys() []const BoxKeyPair  (or similar slice type)
///   - importBoxEphemeralKey(kid: []const u8) ?BoxPublicKey
pub fn KeyRing(comptime T: type) type {
    // Validate required methods at comptime.
    comptime {
        if (!@hasDecl(T, "lookupBoxSecretKey")) {
            @compileError("KeyRing requires a 'lookupBoxSecretKey' method");
        }
        if (!@hasDecl(T, "lookupBoxPublicKey")) {
            @compileError("KeyRing requires a 'lookupBoxPublicKey' method");
        }
        if (!@hasDecl(T, "getAllBoxSecretKeys")) {
            @compileError("KeyRing requires a 'getAllBoxSecretKeys' method");
        }
        if (!@hasDecl(T, "importBoxEphemeralKey")) {
            @compileError("KeyRing requires an 'importBoxEphemeralKey' method");
        }
    }

    return struct {
        /// Returns true if T satisfies the KeyRing interface.
        pub fn isValid() bool {
            return true;
        }
    };
}

// ---------------------------------------------------------------------------
// BasicKeyRing
// ---------------------------------------------------------------------------

/// A simple in-memory keyring for testing and basic usage.
/// Stores a set of BoxKeyPair values and provides lookup by KID.
pub const BasicKeyRing = struct {
    box_keys: []const BoxKeyPair,
    allocator: std.mem.Allocator,

    pub const LookupResult = struct {
        index: usize,
        key: BoxSecretKey,
    };

    /// Looks up a secret key by matching one of the given KIDs against
    /// the public keys stored in this keyring. Returns the index and
    /// matching secret key, or null if no match is found.
    pub fn lookupBoxSecretKey(self: *const BasicKeyRing, kids: []const []const u8) ?LookupResult {
        for (kids, 0..) |kid, i| {
            if (kid.len != BoxPublicKey.key_length) continue;
            for (self.box_keys) |kp| {
                const pk_kid = kp.public_key.toKid();
                if (std.crypto.timing_safe.eql([BoxPublicKey.key_length]u8, pk_kid, kid[0..BoxPublicKey.key_length].*)) {
                    return LookupResult{
                        .index = i,
                        .key = kp.secret_key,
                    };
                }
            }
        }
        return null;
    }

    /// Returns a public key for the given KID, or null if not found.
    pub fn lookupBoxPublicKey(self: *const BasicKeyRing, kid: []const u8) ?BoxPublicKey {
        if (kid.len != BoxPublicKey.key_length) return null;
        for (self.box_keys) |kp| {
            const pk_kid = kp.public_key.toKid();
            if (std.crypto.timing_safe.eql([BoxPublicKey.key_length]u8, pk_kid, kid[0..BoxPublicKey.key_length].*)) {
                return kp.public_key;
            }
        }
        return null;
    }

    /// Returns all box key pairs in the keyring.
    pub fn getAllBoxSecretKeys(self: *const BasicKeyRing) []const BoxKeyPair {
        return self.box_keys;
    }

    /// Imports an ephemeral public key from raw KID bytes.
    /// For the basic keyring, this simply wraps the bytes into a BoxPublicKey.
    pub fn importBoxEphemeralKey(_: *const BasicKeyRing, kid: []const u8) ?BoxPublicKey {
        if (kid.len != BoxPublicKey.key_length) return null;
        return BoxPublicKey{ .bytes = kid[0..BoxPublicKey.key_length].* };
    }
};

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

test "BoxKeyPair generate" {
    const kp = BoxKeyPair.generate();

    // Verify the public and secret keys are the expected lengths.
    try std.testing.expectEqual(@as(usize, 32), kp.public_key.bytes.len);
    try std.testing.expectEqual(@as(usize, 32), kp.secret_key.bytes.len);

    // The secret key's embedded public key should match the pair's public key.
    try std.testing.expect(kp.public_key.eql(kp.secret_key.public_key));

    // The key should not be all zeros (vanishingly unlikely for random keys).
    const zero = [_]u8{0} ** 32;
    try std.testing.expect(!std.mem.eql(u8, &kp.public_key.bytes, &zero));
}

test "BoxKeyPair generate produces unique keys" {
    const kp1 = BoxKeyPair.generate();
    const kp2 = BoxKeyPair.generate();

    // Two randomly generated keys should differ.
    try std.testing.expect(!kp1.public_key.eql(kp2.public_key));
}

test "BoxKeyPair fromSeed is deterministic" {
    const seed = [_]u8{0x42} ** 32;
    const kp1 = try BoxKeyPair.fromSeed(seed);
    const kp2 = try BoxKeyPair.fromSeed(seed);

    try std.testing.expect(kp1.public_key.eql(kp2.public_key));
    try std.testing.expectEqualSlices(u8, &kp1.secret_key.bytes, &kp2.secret_key.bytes);
}

test "SigningKeyPair generate" {
    const kp = SigningKeyPair.generate();

    // Verify the public and secret keys are the expected lengths.
    try std.testing.expectEqual(@as(usize, 32), kp.public_key.bytes.len);
    try std.testing.expectEqual(@as(usize, 64), kp.secret_key.bytes.len);

    // The secret key's embedded public key should match the pair's public key.
    try std.testing.expect(kp.public_key.eql(kp.secret_key.public_key));

    // The key should not be all zeros.
    const zero32 = [_]u8{0} ** 32;
    try std.testing.expect(!std.mem.eql(u8, &kp.public_key.bytes, &zero32));
}

test "SigningKeyPair generate produces unique keys" {
    const kp1 = SigningKeyPair.generate();
    const kp2 = SigningKeyPair.generate();

    try std.testing.expect(!kp1.public_key.eql(kp2.public_key));
}

test "SigningKeyPair fromSeed is deterministic" {
    const seed = [_]u8{0x99} ** 32;
    const kp1 = try SigningKeyPair.fromSeed(seed);
    const kp2 = try SigningKeyPair.fromSeed(seed);

    try std.testing.expect(kp1.public_key.eql(kp2.public_key));
    try std.testing.expectEqualSlices(u8, &kp1.secret_key.bytes, &kp2.secret_key.bytes);
}

test "SigningKeyPair sign and verify" {
    const kp = SigningKeyPair.generate();
    const message = "hello saltpack";
    const sig = try kp.secret_key.sign(message);

    // Verification should succeed.
    try kp.public_key.verify(message, sig);
}

test "BoxPublicKey equality" {
    const bytes_a = [_]u8{0xAA} ** 32;
    const bytes_b = [_]u8{0xBB} ** 32;

    const pk_a = try BoxPublicKey.fromBytes(bytes_a);
    const pk_a2 = try BoxPublicKey.fromBytes(bytes_a);
    const pk_b = try BoxPublicKey.fromBytes(bytes_b);

    try std.testing.expect(pk_a.eql(pk_a2));
    try std.testing.expect(!pk_a.eql(pk_b));
}

test "BoxPublicKey toKid" {
    const bytes = [_]u8{0x42} ** 32;
    const pk = try BoxPublicKey.fromBytes(bytes);
    const kid = pk.toKid();

    // The KID should be exactly the raw key bytes.
    try std.testing.expectEqualSlices(u8, &bytes, &kid);
}

test "BoxPublicKey fromSlice" {
    const bytes = [_]u8{0x42} ** 32;
    const pk = try BoxPublicKey.fromSlice(&bytes);
    try std.testing.expectEqualSlices(u8, &bytes, &pk.bytes);

    // Too short should fail.
    const short = [_]u8{0x42} ** 16;
    try std.testing.expectError(error.BadBoxKey, BoxPublicKey.fromSlice(&short));

    // Too long should fail.
    const long = [_]u8{0x42} ** 48;
    try std.testing.expectError(error.BadBoxKey, BoxPublicKey.fromSlice(&long));
}

test "SigningPublicKey equality" {
    const bytes_a = [_]u8{0xAA} ** 32;
    const bytes_b = [_]u8{0xBB} ** 32;

    const pk_a = try SigningPublicKey.fromBytes(bytes_a);
    const pk_a2 = try SigningPublicKey.fromBytes(bytes_a);
    const pk_b = try SigningPublicKey.fromBytes(bytes_b);

    try std.testing.expect(pk_a.eql(pk_a2));
    try std.testing.expect(!pk_a.eql(pk_b));
}

test "BasicKeyRing lookup" {
    const kp1 = BoxKeyPair.generate();
    const kp2 = BoxKeyPair.generate();
    const keys = [_]BoxKeyPair{ kp1, kp2 };

    const ring = BasicKeyRing{
        .box_keys = &keys,
        .allocator = std.testing.allocator,
    };

    // Look up kp2's public key by its KID.
    const kid2 = kp2.public_key.toKid();
    const kids = [_][]const u8{&kid2};
    const result = ring.lookupBoxSecretKey(&kids);

    try std.testing.expect(result != null);
    try std.testing.expectEqual(@as(usize, 0), result.?.index);
    try std.testing.expect(result.?.key.public_key.eql(kp2.public_key));
}

test "BasicKeyRing lookup with multiple kids" {
    const kp1 = BoxKeyPair.generate();
    const kp2 = BoxKeyPair.generate();
    const keys = [_]BoxKeyPair{kp1};

    const ring = BasicKeyRing{
        .box_keys = &keys,
        .allocator = std.testing.allocator,
    };

    // The first KID is unknown, the second matches kp1.
    const kid_unknown = kp2.public_key.toKid();
    const kid_known = kp1.public_key.toKid();
    const kids = [_][]const u8{ &kid_unknown, &kid_known };
    const result = ring.lookupBoxSecretKey(&kids);

    try std.testing.expect(result != null);
    // Index should be 1, since kid_known was at position 1 in the kids array.
    try std.testing.expectEqual(@as(usize, 1), result.?.index);
    try std.testing.expect(result.?.key.public_key.eql(kp1.public_key));
}

test "BasicKeyRing lookup miss" {
    const kp1 = BoxKeyPair.generate();
    const kp_unknown = BoxKeyPair.generate();
    const keys = [_]BoxKeyPair{kp1};

    const ring = BasicKeyRing{
        .box_keys = &keys,
        .allocator = std.testing.allocator,
    };

    // Look up a KID that is not in the keyring.
    const kid = kp_unknown.public_key.toKid();
    const kids = [_][]const u8{&kid};
    const result = ring.lookupBoxSecretKey(&kids);

    try std.testing.expect(result == null);
}

test "BasicKeyRing lookupBoxPublicKey" {
    const kp = BoxKeyPair.generate();
    const keys = [_]BoxKeyPair{kp};

    const ring = BasicKeyRing{
        .box_keys = &keys,
        .allocator = std.testing.allocator,
    };

    const kid = kp.public_key.toKid();
    const result = ring.lookupBoxPublicKey(&kid);
    try std.testing.expect(result != null);
    try std.testing.expect(result.?.eql(kp.public_key));

    // Miss case.
    const unknown = [_]u8{0xFF} ** 32;
    const miss = ring.lookupBoxPublicKey(&unknown);
    try std.testing.expect(miss == null);
}

test "BasicKeyRing getAllBoxSecretKeys" {
    const kp1 = BoxKeyPair.generate();
    const kp2 = BoxKeyPair.generate();
    const keys = [_]BoxKeyPair{ kp1, kp2 };

    const ring = BasicKeyRing{
        .box_keys = &keys,
        .allocator = std.testing.allocator,
    };

    const all = ring.getAllBoxSecretKeys();
    try std.testing.expectEqual(@as(usize, 2), all.len);
    try std.testing.expect(all[0].public_key.eql(kp1.public_key));
    try std.testing.expect(all[1].public_key.eql(kp2.public_key));
}

test "BasicKeyRing importBoxEphemeralKey" {
    const ring = BasicKeyRing{
        .box_keys = &[_]BoxKeyPair{},
        .allocator = std.testing.allocator,
    };

    const kid = [_]u8{0x42} ** 32;
    const result = ring.importBoxEphemeralKey(&kid);
    try std.testing.expect(result != null);
    try std.testing.expectEqualSlices(u8, &kid, &result.?.bytes);

    // Wrong length should return null.
    const short = [_]u8{0x42} ** 16;
    const miss = ring.importBoxEphemeralKey(&short);
    try std.testing.expect(miss == null);
}

test "KeyRing comptime validation for BasicKeyRing" {
    // This should compile successfully, proving BasicKeyRing satisfies the interface.
    const validated = KeyRing(BasicKeyRing);
    try std.testing.expect(validated.isValid());
}

test "BoxPublicKey.fromBytes rejects all-zero key" {
    const zero = [_]u8{0} ** 32;
    try std.testing.expectError(sp_errors.Error.BadPublicKey, BoxPublicKey.fromBytes(zero));
}

test "BoxPublicKey.fromSlice rejects all-zero key" {
    const zero = [_]u8{0} ** 32;
    try std.testing.expectError(sp_errors.Error.BadPublicKey, BoxPublicKey.fromSlice(&zero));
}

test "BoxSecretKey.fromBytes rejects all-zero key" {
    const zero_secret = [_]u8{0} ** 32;
    // Use a non-zero public key so the error is specifically about the secret key.
    const pk = try BoxPublicKey.fromBytes([_]u8{0x01} ** 32);
    try std.testing.expectError(sp_errors.Error.BadSecretKey, BoxSecretKey.fromBytes(zero_secret, pk));
}

test "BoxPublicKey.fromBytes accepts non-zero key" {
    const bytes = [_]u8{0x42} ** 32;
    const pk = try BoxPublicKey.fromBytes(bytes);
    try std.testing.expectEqualSlices(u8, &bytes, &pk.bytes);
}

test "BoxSecretKey.fromBytes accepts non-zero key" {
    const pk = try BoxPublicKey.fromBytes([_]u8{0x01} ** 32);
    const sk = try BoxSecretKey.fromBytes([_]u8{0x02} ** 32, pk);
    try std.testing.expectEqualSlices(u8, &([_]u8{0x02} ** 32), &sk.bytes);
}

test "BoxKeyPair.wipe zeros the secret key" {
    var kp = BoxKeyPair.generate();
    // Sanity: the secret key should not be all zeros after generation.
    const zero32 = [_]u8{0} ** 32;
    try std.testing.expect(!std.mem.eql(u8, &kp.secret_key.bytes, &zero32));

    kp.wipe();
    try std.testing.expectEqualSlices(u8, &zero32, &kp.secret_key.bytes);
}

test "SigningKeyPair.wipe zeros the secret key" {
    var kp = SigningKeyPair.generate();
    // Sanity: the secret key should not be all zeros after generation.
    const zero64 = [_]u8{0} ** 64;
    try std.testing.expect(!std.mem.eql(u8, &kp.secret_key.bytes, &zero64));

    kp.wipe();
    try std.testing.expectEqualSlices(u8, &zero64, &kp.secret_key.bytes);
}

test "SigningPublicKey.fromBytes rejects all-zero key" {
    const zero = [_]u8{0} ** 32;
    try std.testing.expectError(sp_errors.Error.BadPublicKey, SigningPublicKey.fromBytes(zero));
}

test "SigningPublicKey.fromBytes accepts non-zero key" {
    const bytes = [_]u8{0x42} ** 32;
    const pk = try SigningPublicKey.fromBytes(bytes);
    try std.testing.expectEqualSlices(u8, &bytes, &pk.bytes);
}
