# saltpack-zig

**WARNING:  This code was extensively vibed;  it's just for me right now**

A Zig implementation of the [saltpack](https://saltpack.org) cryptographic messaging format.

## Features

- **Encrypt / Decrypt** -- NaCl-based authenticated encryption for one or more receivers
- **Sign / Verify** -- Ed25519 attached and detached signatures
- **Signcrypt** -- combined encryption + signing in a single operation (v2)
- **Armor** -- BaseX armored encoding with human-readable headers
- **Streaming APIs** -- `EncryptStream`, `DecryptStream`, `SignStream`, `VerifyStream` for processing data incrementally
- **Saltpack v1 and v2** support

## Installation

Add `saltpack-zig` as a dependency in your `build.zig.zon`:

```zig
.dependencies = .{
    .saltpack = .{
        .url = "https://github.com/<owner>/saltpack-zig/archive/<commit>.tar.gz",
        .hash = "<hash>",
    },
},
```

Then import in your `build.zig`:

```zig
const saltpack_dep = b.dependency("saltpack", .{
    .target = target,
    .optimize = optimize,
});
your_module.addImport("saltpack", saltpack_dep.module("saltpack"));
```

## Quick Usage

### Encrypt and decrypt

```zig
const sp = @import("saltpack");
const allocator = std.heap.page_allocator;

// Generate keys
const sender_kp = sp.BoxKeyPair.generate();
const receiver_kp = sp.BoxKeyPair.generate();

// Encrypt
const receiver_pks = [_]sp.BoxPublicKey{receiver_kp.public_key};
const ciphertext = try sp.seal(allocator, "hello, saltpack!", sender_kp.secret_key, &receiver_pks, .{});
defer allocator.free(ciphertext);

// Decrypt
const keyring = [_]sp.BoxKeyPair{receiver_kp};
const result = try sp.open(allocator, ciphertext, &keyring);
defer result.deinit();
// result.plaintext == "hello, saltpack!"
```

### Sign and verify

```zig
const sp = @import("saltpack");
const allocator = std.heap.page_allocator;

const signer = sp.SigningKeyPair.generate();

// Sign (attached)
const signed = try sp.signAttached(allocator, "hello, saltpack!", signer.secret_key, .{});
defer signed.deinit();

// Verify
const verified = try sp.verifyAttached(allocator, signed.data);
defer verified.deinit();
// verified.plaintext == "hello, saltpack!"
```

### Signcryption

Signcryption combines encryption and signing into a single operation (v2 only).
The message is encrypted for the specified receivers and signed by the sender
in one pass.

```zig
const sp = @import("saltpack");
const allocator = std.heap.page_allocator;

const signing_kp = sp.SigningKeyPair.generate();
const receiver_kp = sp.BoxKeyPair.generate();

// Signcrypt
const receiver_box_keys = [_]sp.BoxPublicKey{receiver_kp.public_key};
const ciphertext = try sp.signcryptSeal(allocator, "secret signed message", signing_kp.secret_key, .{
    .receiver_box_keys = &receiver_box_keys,
});
defer allocator.free(ciphertext);

// Open
const keyring = [_]sp.BoxKeyPair{receiver_kp};
const result = try sp.signcryptOpen(allocator, ciphertext, &keyring);
defer result.deinit();
// result.plaintext == "secret signed message"
// result.key_info.sender_is_anonymous == false
```

### Streaming API

For large messages or when data arrives incrementally, use the streaming API.
`EncryptStream` and `SignStream` are writers; `DecryptStream` and `VerifyStream`
are readers.

The stream types are parameterized by an underlying writer/reader type. In Zig 0.15,
`ArrayList` does not have a built-in `.writer()` method, so you need a small adapter
struct. Here is the pattern used by the library's own tests:

```zig
const std = @import("std");
const sp = @import("saltpack");

const TestWriter = struct {
    list: *std.ArrayList(u8),
    alloc: std.mem.Allocator,

    pub const WriteError = std.mem.Allocator.Error;

    pub fn write(self: TestWriter, data: []const u8) WriteError!usize {
        self.list.appendSlice(self.alloc, data) catch |err| return err;
        return data.len;
    }

    pub fn writeAll(self: TestWriter, data: []const u8) WriteError!void {
        self.list.appendSlice(self.alloc, data) catch |err| return err;
    }
};

const allocator = std.heap.page_allocator;
const sender_kp = sp.BoxKeyPair.generate();
const receiver_kp = sp.BoxKeyPair.generate();
const receiver_pks = [_]sp.BoxPublicKey{receiver_kp.public_key};

// Streaming encrypt into a buffer
var output: std.ArrayList(u8) = .empty;
defer output.deinit(allocator);
const tw = TestWriter{ .list = &output, .alloc = allocator };

var enc = try sp.EncryptStream(TestWriter).init(
    allocator, tw, sender_kp.secret_key, &receiver_pks, .{},
);
defer enc.deinit();

_ = try enc.write("hello, ");
_ = try enc.write("streaming saltpack!");
try enc.finish();

// Streaming decrypt back
const FBS = std.io.FixedBufferStream([]const u8);
var fbs = std.io.fixedBufferStream(@as([]const u8, output.items));
const keyring = [_]sp.BoxKeyPair{receiver_kp};
var dec = try sp.DecryptStream(FBS.Reader).init(
    allocator, fbs.reader(), &keyring,
);
defer dec.deinit();

var plaintext: std.ArrayList(u8) = .empty;
defer plaintext.deinit(allocator);
var buf: [4096]u8 = undefined;
while (true) {
    const n = dec.read(&buf) catch break;
    if (n == 0) break;
    try plaintext.appendSlice(allocator, buf[0..n]);
}
// plaintext.items == "hello, streaming saltpack!"
```

### Armored messages

Armored encoding wraps binary saltpack messages in human-readable Base62 with
branded headers, suitable for pasting into emails or chat messages.

```zig
const sp = @import("saltpack");
const allocator = std.heap.page_allocator;

const sender_kp = sp.BoxKeyPair.generate();
const receiver_kp = sp.BoxKeyPair.generate();
const receiver_pks = [_]sp.BoxPublicKey{receiver_kp.public_key};

// Encrypt and armor (pass a brand name or null)
const armored = try sp.armorSeal(allocator, "hello, armored!", sender_kp.secret_key, &receiver_pks, .{}, "MYAPP");
defer allocator.free(armored);
// armored starts with "BEGIN MYAPP SALTPACK ENCRYPTED MESSAGE."

// Dearmor and decrypt
const keyring = [_]sp.BoxKeyPair{receiver_kp};
const result = try sp.armorOpen(allocator, armored, &keyring);
defer result.deinit();
// result.plaintext == "hello, armored!"
```

### Advanced options

#### Version policy enforcement

Use `*WithOptions` variants to restrict accepted protocol versions, defending
against version downgrade attacks:

```zig
const result = try sp.openWithOptions(allocator, ciphertext, &keyring, .{
    .version_policy = sp.VersionPolicy.v2Only(),
});
```

Version policies are also available for verification:

```zig
const result = try sp.verifyAttachedWithOptions(allocator, signed_msg, .{
    .version_policy = sp.VersionPolicy.v2Only(),
});
```

#### Signer identity pinning

The `*From` variants verify that a message was produced by a specific signer,
preventing the common mistake of ignoring the signer field in the result:

```zig
// Attached signature -- rejects if signer != expected_key
const result = try sp.verifyAttachedFrom(allocator, signed_msg, expected_key);

// Detached signature
const result = try sp.verifyDetachedFrom(allocator, message, sig_msg, expected_key);

// Signcryption -- rejects anonymous senders and wrong signers
const result = try sp.signcryptOpenFrom(allocator, ct, &keyring, expected_signer);
```

#### Safe error handling for server contexts

Detailed saltpack errors can leak processing progress to attackers. Use
`toSafeError()` to collapse them into opaque categories before returning
errors to untrusted callers:

```zig
const result = sp.open(allocator, ct, &keyring) catch |err| {
    log.err("internal: {}", .{err});   // log full detail
    return sp.toSafeError(err);        // return opaque SafeError to client
};
```

`toSafeError` maps all errors to one of four categories: `decryption_failed`,
`verification_failed`, `invalid_input`, or `internal_error`.

## Benchmarks

Run the benchmark suite with:

```sh
zig build bench -Doptimize=ReleaseFast
```

This exercises the core encrypt/decrypt, sign/verify, signcrypt, streaming,
armor, and key-generation paths at various message sizes and prints per-operation
timing and throughput numbers.

## Thread Safety

The one-shot convenience APIs (`seal`, `open`, `signAttached`, `verifyAttached`,
`signcryptSeal`, `signcryptOpen`, etc.) are safe to call concurrently from
multiple threads -- they do not share mutable state.

Stream instances (`EncryptStream`, `DecryptStream`, `SignStream`, `VerifyStream`)
are **not** thread-safe. Each stream must be used from a single thread at a time.
If you need concurrent streaming operations, create separate stream instances.

## Supported Zig Version

Requires **Zig 0.15+**.

## Specification

This library implements the saltpack messaging format as defined at
[saltpack.org](https://saltpack.org).

## License

MIT -- see [LICENSE](LICENSE).
