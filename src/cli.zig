const std = @import("std");
const Allocator = std.mem.Allocator;
const testing = std.testing;
const testallocator = testing.allocator;

const RawArgs = struct {
    allocator: Allocator,
    args: [][:0]u8,
    executable_name: []u8,
    map: std.StringHashMap([]const u8),

    const Self = @This();

    pub fn deinit(self: *Self) void {
        std.process.argsFree(self.allocator, self.args);
        self.map.deinit();
    }
};

const USAGE_STRING =
    \\Usage: {s} [command] [options]
    \\
    \\Commands:
    \\    None, yet!
    \\
    \\Options:
    \\    --help        Print usage
    \\
;

/// Print the usage message using the executable name.
pub fn print_usage(args: RawArgs) void {
    std.debug.print(USAGE_STRING, .{args.executable_name});
}

fn arg_is_flag(arg: []u8) bool {
    return std.mem.startsWith(u8, arg, "--");
}

/// Parse command-line arguments into a `RawArgs` structure.
///
/// Arguments with values (e.g. `--something 8080`) are stored as key-value pairs.
/// Flags not followed by anything (e.g `--something`) are stored with an empty value.
///
/// Example:
/// ```sh
/// ./app --port 8080 --help
/// ```
/// Results in:
/// ```
/// map = {
///     "--port": "8080",
///     "--help": ""
/// }
/// ```
///
///
pub fn parseArgs(allocator: Allocator) !RawArgs {
    const args = try std.process.argsAlloc(allocator);
    if (args.len == 0) return error.MissingExecutable;

    var result = RawArgs{
        .allocator = allocator,
        .args = args,
        .map = std.StringHashMap([]const u8).init(allocator),
        .executable_name = args[0],
    };

    if (args.len == 1) return result;
    if (args.len == 2) {
        try result.map.put(args[1], "");
        return result;
    }

    // skip the executable name and loop for each arg
    for (1..args.len - 1) |i| {
        const prev = args[i];
        const curr = args[i + 1];

        try result.map.put(curr, "");
        if (!arg_is_flag(curr) and arg_is_flag(prev)) {
            try result.map.put(prev, curr);
        }
    }

    return result;
}

pub fn get_bool(args: RawArgs, key: []const u8) bool {
    return args.map.contains(key);
}

pub fn get(args: RawArgs, key: []const u8) []u8 {
    return args.map.get(key);
}

pub fn get_int(comptime T: type, args: RawArgs, key: []const u8) T {
    return std.fmt.parseInt(T, args.map.get(key), 10);
}

/// Shortcut for `get_int` for `i32` type.
pub fn get_i32(args: RawArgs, key: []const u8) i32 {
    return get_int(i32, args, key);
}

pub fn print_raw_map(args: RawArgs) void {
    var iterator = args.map.iterator();
    while (iterator.next()) |key| {
        std.debug.print("{s}: {s}\n", .{ key.key_ptr.*, key.value_ptr.* });
    }
}

