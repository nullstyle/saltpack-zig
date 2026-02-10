const std = @import("std");
const saltpack = @import("saltpack");

const BoxKeyPair = saltpack.BoxKeyPair;
const BoxPublicKey = saltpack.BoxPublicKey;
const SigningKeyPair = saltpack.SigningKeyPair;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

/// Format nanoseconds into a human-readable duration string.
fn formatDuration(buf: []u8, ns: u64) []const u8 {
    if (ns < 1_000) {
        return std.fmt.bufPrint(buf, "{d} ns", .{ns}) catch "???";
    } else if (ns < 1_000_000) {
        const us: f64 = @as(f64, @floatFromInt(ns)) / 1_000.0;
        return std.fmt.bufPrint(buf, "{d:.2} us", .{us}) catch "???";
    } else if (ns < 1_000_000_000) {
        const ms: f64 = @as(f64, @floatFromInt(ns)) / 1_000_000.0;
        return std.fmt.bufPrint(buf, "{d:.2} ms", .{ms}) catch "???";
    } else {
        const s: f64 = @as(f64, @floatFromInt(ns)) / 1_000_000_000.0;
        return std.fmt.bufPrint(buf, "{d:.2} s", .{s}) catch "???";
    }
}

/// Print a benchmark result line with throughput.
fn printResult(name: []const u8, iterations: u64, total_ns: u64, data_size: ?usize) void {
    const per_op_ns: u64 = if (iterations > 0) total_ns / iterations else 0;
    var total_buf: [64]u8 = undefined;
    var per_op_buf: [64]u8 = undefined;
    const total_str = formatDuration(&total_buf, total_ns);
    const per_op_str = formatDuration(&per_op_buf, per_op_ns);

    if (data_size) |size| {
        const bytes_per_sec: f64 = if (per_op_ns > 0)
            @as(f64, @floatFromInt(size)) / (@as(f64, @floatFromInt(per_op_ns)) / 1_000_000_000.0)
        else
            0.0;
        const mb_per_sec: f64 = bytes_per_sec / (1024.0 * 1024.0);
        std.debug.print("  {s:<45} {d:>6} iters  {s:>12} total  {s:>12}/op  {d:>8.2} MB/s\n", .{
            name, iterations, total_str, per_op_str, mb_per_sec,
        });
    } else {
        std.debug.print("  {s:<45} {d:>6} iters  {s:>12} total  {s:>12}/op\n", .{
            name, iterations, total_str, per_op_str,
        });
    }
}

/// Generate a deterministic test message of a given size.
fn generateMessage(allocator: std.mem.Allocator, size: usize) ![]u8 {
    const msg = try allocator.alloc(u8, size);
    // Fill with a repeating pattern for reproducibility.
    for (msg, 0..) |*b, i| {
        b.* = @truncate(i);
    }
    return msg;
}

/// Writer adapter for std.ArrayList(u8) that passes allocator per-call.
/// Matches the Zig 0.15 unmanaged ArrayList pattern used in this codebase.
const ListWriter = struct {
    list: *std.ArrayList(u8),
    alloc: std.mem.Allocator,

    pub const Error = std.mem.Allocator.Error;
    pub const WriteError = std.mem.Allocator.Error;

    pub fn write(self: ListWriter, data: []const u8) WriteError!usize {
        self.list.appendSlice(self.alloc, data) catch |err| return err;
        return data.len;
    }
};

const FBS = std.io.FixedBufferStream([]const u8);

// ---------------------------------------------------------------------------
// Benchmarks
// ---------------------------------------------------------------------------

fn benchEncryptDecrypt(allocator: std.mem.Allocator) !void {
    std.debug.print("\n--- Encrypt / Decrypt ---\n", .{});

    const sizes = [_]struct { size: usize, name: []const u8, iters: u64 }{
        .{ .size = 1024, .name = "1 KB", .iters = 100 },
        .{ .size = 64 * 1024, .name = "64 KB", .iters = 50 },
        .{ .size = 1024 * 1024, .name = "1 MB", .iters = 10 },
    };

    const sender_kp = BoxKeyPair.generate();
    const receiver_kp = BoxKeyPair.generate();
    const receiver_pks = [_]BoxPublicKey{receiver_kp.public_key};
    const keyring = [_]BoxKeyPair{receiver_kp};

    for (sizes) |entry| {
        const msg = try generateMessage(allocator, entry.size);
        defer allocator.free(msg);

        // Benchmark encrypt
        {
            var timer = try std.time.Timer.start();
            var i: u64 = 0;
            while (i < entry.iters) : (i += 1) {
                const ct = try saltpack.seal(allocator, msg, sender_kp.secret_key, &receiver_pks, .{});
                allocator.free(ct);
            }
            const elapsed = timer.read();
            var name_buf: [64]u8 = undefined;
            const name = std.fmt.bufPrint(&name_buf, "encrypt {s}", .{entry.name}) catch "???";
            printResult(name, entry.iters, elapsed, entry.size);
        }

        // Encrypt once for decrypt benchmark
        const ct = try saltpack.seal(allocator, msg, sender_kp.secret_key, &receiver_pks, .{});
        defer allocator.free(ct);

        // Benchmark decrypt
        {
            var timer = try std.time.Timer.start();
            var i: u64 = 0;
            while (i < entry.iters) : (i += 1) {
                const result = try saltpack.open(allocator, ct, &keyring);
                result.deinit();
            }
            const elapsed = timer.read();
            var name_buf: [64]u8 = undefined;
            const name = std.fmt.bufPrint(&name_buf, "decrypt {s}", .{entry.name}) catch "???";
            printResult(name, entry.iters, elapsed, entry.size);
        }
    }
}

fn benchSignVerify(allocator: std.mem.Allocator) !void {
    std.debug.print("\n--- Sign / Verify (attached) ---\n", .{});

    const sizes = [_]struct { size: usize, name: []const u8, iters: u64 }{
        .{ .size = 1024, .name = "1 KB", .iters = 100 },
        .{ .size = 64 * 1024, .name = "64 KB", .iters = 50 },
        .{ .size = 1024 * 1024, .name = "1 MB", .iters = 10 },
    };

    const signer = SigningKeyPair.generate();

    for (sizes) |entry| {
        const msg = try generateMessage(allocator, entry.size);
        defer allocator.free(msg);

        // Benchmark sign
        {
            var timer = try std.time.Timer.start();
            var i: u64 = 0;
            while (i < entry.iters) : (i += 1) {
                const signed = try saltpack.signAttached(allocator, msg, signer.secret_key, .{});
                signed.deinit();
            }
            const elapsed = timer.read();
            var name_buf: [64]u8 = undefined;
            const name = std.fmt.bufPrint(&name_buf, "sign attached {s}", .{entry.name}) catch "???";
            printResult(name, entry.iters, elapsed, entry.size);
        }

        // Sign once for verify benchmark
        const signed = try saltpack.signAttached(allocator, msg, signer.secret_key, .{});
        defer signed.deinit();

        // Benchmark verify
        {
            var timer = try std.time.Timer.start();
            var i: u64 = 0;
            while (i < entry.iters) : (i += 1) {
                const result = try saltpack.verifyAttached(allocator, signed.data);
                result.deinit();
            }
            const elapsed = timer.read();
            var name_buf: [64]u8 = undefined;
            const name = std.fmt.bufPrint(&name_buf, "verify attached {s}", .{entry.name}) catch "???";
            printResult(name, entry.iters, elapsed, entry.size);
        }
    }
}

fn benchSigncrypt(allocator: std.mem.Allocator) !void {
    std.debug.print("\n--- Signcrypt / Open ---\n", .{});

    const signing_kp = SigningKeyPair.generate();
    const box_kp = BoxKeyPair.generate();
    const receiver_box_keys = [_]BoxPublicKey{box_kp.public_key};
    const keyring = [_]BoxKeyPair{box_kp};

    const msg = try generateMessage(allocator, 1024);
    defer allocator.free(msg);

    const iters: u64 = 100;

    // Benchmark signcrypt seal
    {
        var timer = try std.time.Timer.start();
        var i: u64 = 0;
        while (i < iters) : (i += 1) {
            const ct = try saltpack.signcryptSeal(allocator, msg, signing_kp.secret_key, .{
                .receiver_box_keys = &receiver_box_keys,
            });
            allocator.free(ct);
        }
        const elapsed = timer.read();
        printResult("signcrypt seal 1 KB", iters, elapsed, 1024);
    }

    // Seal once for open benchmark
    const ct = try saltpack.signcryptSeal(allocator, msg, signing_kp.secret_key, .{
        .receiver_box_keys = &receiver_box_keys,
    });
    defer allocator.free(ct);

    // Benchmark signcrypt open
    {
        var timer = try std.time.Timer.start();
        var i: u64 = 0;
        while (i < iters) : (i += 1) {
            const result = try saltpack.signcryptOpen(allocator, ct, &keyring);
            result.deinit();
        }
        const elapsed = timer.read();
        printResult("signcrypt open 1 KB", iters, elapsed, 1024);
    }
}

fn benchStreamEncryptDecrypt(allocator: std.mem.Allocator) !void {
    std.debug.print("\n--- Streaming Encrypt / Decrypt (1 MB) ---\n", .{});

    const msg_size: usize = 1024 * 1024;
    const msg = try generateMessage(allocator, msg_size);
    defer allocator.free(msg);

    const sender_kp = BoxKeyPair.generate();
    const receiver_kp = BoxKeyPair.generate();
    const receiver_pks = [_]BoxPublicKey{receiver_kp.public_key};
    const keyring = [_]BoxKeyPair{receiver_kp};

    const iters: u64 = 10;

    // Benchmark streaming encrypt
    {
        var timer = try std.time.Timer.start();
        var i: u64 = 0;
        while (i < iters) : (i += 1) {
            var output: std.ArrayList(u8) = .empty;
            defer output.deinit(allocator);
            const lw = ListWriter{ .list = &output, .alloc = allocator };

            var enc_stream = try saltpack.EncryptStream(ListWriter).init(
                allocator,
                lw,
                sender_kp.secret_key,
                &receiver_pks,
                .{},
            );
            defer enc_stream.deinit();

            _ = try enc_stream.write(msg);
            try enc_stream.finish();
        }
        const elapsed = timer.read();
        printResult("stream encrypt 1 MB", iters, elapsed, msg_size);
    }

    // Encrypt once for streaming decrypt benchmark
    var ct_buf: std.ArrayList(u8) = .empty;
    defer ct_buf.deinit(allocator);
    {
        const lw = ListWriter{ .list = &ct_buf, .alloc = allocator };
        var enc_stream = try saltpack.EncryptStream(ListWriter).init(
            allocator,
            lw,
            sender_kp.secret_key,
            &receiver_pks,
            .{},
        );
        defer enc_stream.deinit();
        _ = try enc_stream.write(msg);
        try enc_stream.finish();
    }

    // Benchmark streaming decrypt
    {
        var timer = try std.time.Timer.start();
        var i: u64 = 0;
        while (i < iters) : (i += 1) {
            var fbs = std.io.fixedBufferStream(@as([]const u8, ct_buf.items));
            var dec_stream = try saltpack.DecryptStream(FBS.Reader).init(
                allocator,
                fbs.reader(),
                &keyring,
            );
            defer dec_stream.deinit();

            // Read all decrypted output
            var out: std.ArrayList(u8) = .empty;
            defer out.deinit(allocator);
            var read_buf: [8192]u8 = undefined;
            while (true) {
                const n = dec_stream.read(&read_buf) catch |err| switch (err) {
                    error.EndOfStream => break,
                    else => return err,
                };
                if (n == 0) break;
                out.appendSlice(allocator, read_buf[0..n]) catch |err| return err;
            }
        }
        const elapsed = timer.read();
        printResult("stream decrypt 1 MB", iters, elapsed, msg_size);
    }
}

fn benchArmor(allocator: std.mem.Allocator) !void {
    std.debug.print("\n--- Armor Encode / Decode ---\n", .{});

    const sender_kp = BoxKeyPair.generate();
    const receiver_kp = BoxKeyPair.generate();
    const receiver_pks = [_]BoxPublicKey{receiver_kp.public_key};
    const keyring = [_]BoxKeyPair{receiver_kp};

    const msg = try generateMessage(allocator, 1024);
    defer allocator.free(msg);

    const iters: u64 = 100;

    // Benchmark armored encrypt (seal + armor encode)
    {
        var timer = try std.time.Timer.start();
        var i: u64 = 0;
        while (i < iters) : (i += 1) {
            const armored = try saltpack.armorSeal(allocator, msg, sender_kp.secret_key, &receiver_pks, .{}, null);
            allocator.free(armored);
        }
        const elapsed = timer.read();
        printResult("armor seal 1 KB", iters, elapsed, 1024);
    }

    // Encode once for decode benchmark
    const armored = try saltpack.armorSeal(allocator, msg, sender_kp.secret_key, &receiver_pks, .{}, null);
    defer allocator.free(armored);

    // Benchmark armored decrypt (armor decode + open)
    {
        var timer = try std.time.Timer.start();
        var i: u64 = 0;
        while (i < iters) : (i += 1) {
            const result = try saltpack.armorOpen(allocator, armored, &keyring);
            result.deinit();
        }
        const elapsed = timer.read();
        printResult("armor open 1 KB", iters, elapsed, 1024);
    }
}

fn benchKeyGeneration() void {
    std.debug.print("\n--- Key Generation ---\n", .{});

    const box_iters: u64 = 1000;
    const sign_iters: u64 = 1000;

    // Benchmark BoxKeyPair generation
    {
        var timer = std.time.Timer.start() catch {
            std.debug.print("  timer unavailable\n", .{});
            return;
        };
        var i: u64 = 0;
        while (i < box_iters) : (i += 1) {
            _ = BoxKeyPair.generate();
        }
        const elapsed = timer.read();
        printResult("BoxKeyPair.generate()", box_iters, elapsed, null);
    }

    // Benchmark SigningKeyPair generation
    {
        var timer = std.time.Timer.start() catch {
            std.debug.print("  timer unavailable\n", .{});
            return;
        };
        var i: u64 = 0;
        while (i < sign_iters) : (i += 1) {
            _ = SigningKeyPair.generate();
        }
        const elapsed = timer.read();
        printResult("SigningKeyPair.generate()", sign_iters, elapsed, null);
    }
}

// ---------------------------------------------------------------------------
// Main
// ---------------------------------------------------------------------------

pub fn main() !void {
    const allocator = std.heap.page_allocator;

    std.debug.print("=== saltpack-zig benchmarks ===\n", .{});

    try benchEncryptDecrypt(allocator);
    try benchSignVerify(allocator);
    try benchSigncrypt(allocator);
    try benchStreamEncryptDecrypt(allocator);
    try benchArmor(allocator);
    benchKeyGeneration();

    std.debug.print("\n=== done ===\n", .{});
}
