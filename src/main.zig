//! By convention, main.zig is where your main function lives in the case that
//! you are building an executable. If you are making a library, the convention
//! is to delete this file and start with root.zig instead.

const std = @import("std");
const linux = std.os.linux;
const os = std.os;

// linux.getErrno(value) != .SUCCESS

pub fn child(_: usize) callconv(.C) u8 {
    const bin = "/bin/ls";
    const argv: [*:null]const ?[*:0]const u8 = &[_:null]?[*:0]const u8{ bin, "-al" };
    const envp: [*:null]const ?[*:0]const u8 = &[_:null]?[*:0]const u8{};
    const newRoot = "/tmp/alpine";
    const ret = linux.chroot(newRoot);
    if (linux.E.init(ret) != .SUCCESS) {
        std.debug.panic("chroot failed\n", .{});
    }
    std.debug.print("hey\n", .{});
    _ = linux.execve(bin, argv, envp);
    std.debug.print("panic", .{});
    return 0;
}

pub fn main() !void {
    var ptid: i32 = 0;
    var ctid: i32 = 0;
    var general_purpose_allocator = std.heap.GeneralPurposeAllocator(.{}){};
    defer std.debug.assert(general_purpose_allocator.deinit() == .ok);
    const gpa = general_purpose_allocator.allocator();
    const stack = try gpa.alloc(u8, 1024);
    const pid = linux.clone(&child, @intFromPtr(&stack), 17, 0, &ptid, 0, &ctid);
    if (linux.E.init(pid) != .SUCCESS) {
        std.debug.panic("panic\n", .{});
    }

    if (pid != 0) { // parent
        std.debug.print("{}\n", .{pid});
        var status: u32 = undefined;
        const ret = linux.waitpid(-1, &status, 0);
        const wait_err = std.posix.waitpid(-1, 0).status;
        const err = linux.E.init(ret);
        if (wait_err != 0) {
            std.debug.panic("waitpid failed: {} {} \n", .{ err, ret });
        }
    }
}
