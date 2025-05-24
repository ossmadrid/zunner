//! By convention, main.zig is where your main function lives in the case that
//! you are building an executable. If you are making a library, the convention
//! is to delete this file and start with root.zig instead.

const std = @import("std");
const linux = @import("std").os.linux;

// linux.getErrno(value) != .SUCCESS

pub fn main() !void {
    const bin = "/bin/ls";
    const argv: [*:null]const ?[*:0]const u8 = &[_:null]?[*:0]const u8{ bin, "/" };
    const envp: [*:null]const ?[*:0]const u8 = &[_:null]?[*:0]const u8{};
    const newRoot = "/tmp/alpine";

    var ret = linux.fork();
    if (linux.E.init(ret) != .SUCCESS) {
        std.debug.panic("panic\n", .{});
    }

    if (ret != 0) { // parent
        std.debug.print("{}\n", .{ret});
    } else { // child
        ret = linux.chroot(newRoot);
        if (linux.E.init(ret) != .SUCCESS) {
            std.debug.panic("chroot failed\n", .{});
        }
        std.debug.print("hey\n", .{});
        _ = linux.execve(bin, argv, envp);
        std.debug.print("panic", .{});
    }
}
