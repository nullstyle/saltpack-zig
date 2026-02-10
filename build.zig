const std = @import("std");

pub fn build(b: *std.Build) void {
    const target = b.standardTargetOptions(.{});
    const optimize = b.standardOptimizeOption(.{});

    // zig-msgpack dependency
    const msgpack_dep = b.dependency("zig_msgpack", .{
        .target = target,
        .optimize = optimize,
    });

    // Library module
    const lib_mod = b.addModule("saltpack", .{
        .root_source_file = b.path("src/saltpack.zig"),
        .target = target,
        .optimize = optimize,
    });
    lib_mod.addImport("msgpack", msgpack_dep.module("msgpack"));

    // Static library artifact
    const lib = b.addLibrary(.{
        .linkage = .static,
        .name = "saltpack",
        .root_module = lib_mod,
    });
    b.installArtifact(lib);

    // Tests
    const lib_unit_tests = b.addTest(.{
        .root_module = lib_mod,
    });
    const run_lib_unit_tests = b.addRunArtifact(lib_unit_tests);
    const test_step = b.step("test", "Run unit tests");
    test_step.dependOn(&run_lib_unit_tests.step);

    // Fuzz tests
    //
    // The fuzz targets live in src/fuzz.zig and are also included in the
    // regular test suite via the saltpack.zig import. This dedicated step
    // provides a convenient entry point for continuous fuzzing:
    //
    //   zig build fuzz              -- single-pass smoke test (same as `test`)
    //   zig build fuzz -- --fuzz    -- continuous fuzz mode with web UI
    //
    const fuzz_mod = b.addModule("fuzz", .{
        .root_source_file = b.path("src/fuzz.zig"),
        .target = target,
        .optimize = optimize,
    });
    fuzz_mod.addImport("msgpack", msgpack_dep.module("msgpack"));

    const fuzz_tests = b.addTest(.{
        .root_module = fuzz_mod,
    });
    const run_fuzz_tests = b.addRunArtifact(fuzz_tests);
    const fuzz_step = b.step("fuzz", "Run fuzz tests (add -- --fuzz for continuous fuzzing)");
    fuzz_step.dependOn(&run_fuzz_tests.step);

    // Benchmarks
    const bench_mod = b.addModule("bench", .{
        .root_source_file = b.path("src/bench.zig"),
        .target = target,
        .optimize = optimize,
    });
    bench_mod.addImport("saltpack", lib_mod);
    bench_mod.addImport("msgpack", msgpack_dep.module("msgpack"));

    const bench_exe = b.addExecutable(.{
        .name = "bench",
        .root_module = bench_mod,
    });
    b.installArtifact(bench_exe);

    const run_bench = b.addRunArtifact(bench_exe);
    const bench_step = b.step("bench", "Run benchmarks");
    bench_step.dependOn(&run_bench.step);
}
