const std = @import("std");
const constants = @import("constants.zig");

pub fn generateContainerId(buf: []u8) !void {
    const file = try std.fs.openFileAbsolute("/dev/urandom", .{ .mode = .read_only });
    defer file.close();
    var bytes: [constants.CONTAINER_ID_SIZE_BYTES]u8 = undefined;
    _ = try file.read(&bytes);
    const fmt = std.fmt.fmtSliceHexLower(&bytes);
    _ = try std.fmt.bufPrint(buf, "{}", .{fmt});
}
