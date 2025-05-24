const std = @import("std");
const test_allocator = std.testing.allocator;
const expect = std.testing.expect;

const Config = struct {
    architecture: []u8,
    config: struct {
        Env: [][]u8,
        Cmd: [][]u8,
        WorkingDir: []u8,
    },
    created: []u8,
    history: []struct {
        created: []u8,
        created_by: []u8,
        comment: []u8,
        empty_layer: bool = false,
    },
    os: []u8,
    rootfs: struct {
        type: []u8,
        diff_ids: [][]u8,
    },
    variant: []u8,
};

pub fn parseConfig(allocator: std.mem.Allocator, input: []const u8) !std.json.Parsed(Config) {
    return try std.json.parseFromSlice(Config, allocator, input, .{});
}

test "config json parser" {
    const file = try std.fs.cwd().openFile("testdata/config.json", .{});
    defer file.close();

    const fileStat = try file.stat();
    const input = try file.readToEndAlloc(test_allocator, fileStat.size);
    defer test_allocator.free(input);
    const parsed = try parseConfig(test_allocator, input);
    defer parsed.deinit();
    try expect(std.mem.eql(u8, parsed.value.architecture, "arm64"));
    try expect(std.mem.eql(u8, parsed.value.os, "linux"));
    try expect(std.mem.eql(u8, parsed.value.variant, "v8"));
}
