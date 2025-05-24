//! By convention, main.zig is where your main function lives in the case that
//! you are building an executable. If you are making a library, the convention
//! is to delete this file and start with root.zig instead.

const std = @import("std");
const linux = std.os.linux;
const os = std.os;
const cli = @import("cli.zig");

const SIGCHLD = 17;

pub fn child(_: usize) callconv(.C) u8 {    
    const bin = "/bin/sh";
    const argv: [*:null]const ?[*:0]const u8 = &[_:null]?[*:0]const u8{ bin, "-i" };
    const envp: [*:null]const ?[*:0]const u8 = &[_:null]?[*:0]const u8{};
    const newRoot = "./alpine";
    const ret = linux.chroot(newRoot);
    if (linux.E.init(ret) != .SUCCESS) {
        std.debug.panic("chroot failed: {}\n", .{linux.E.init(ret)});
    }
    std.debug.print("hey\n", .{});
    _ = linux.chdir("/");
    _ = linux.execve(bin, argv, envp);
    std.debug.print("panic", .{});
    return 0;
}

pub fn main() !u8 {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    //defer std.debug.assert(gpa.deinit() == .ok);
    const allocator = gpa.allocator();
    const args = cli.parseArgs(allocator) catch {
        std.debug.panic("Invalid args or an error occurred", .{});
    };

    if (cli.get_bool(args, "--help")) {
        cli.print_usage(args);
        return 0;
    }
    
    var ptid: i32 = 0;
    var ctid: i32 = 0;
    const stack = try allocator.alloc(u8, 1024);
    const pid = linux.clone(&child, @intFromPtr(&stack), SIGCHLD, 0, &ptid, 0, &ctid);
    if (linux.E.init(pid) != .SUCCESS) {
        std.debug.panic("panic\n", .{});
    }

    if (pid != 0) { // parent
        std.debug.print("{}\n", .{pid});
        const ret = linux.waitpid(-1, undefined, 0);
        if (linux.E.init(ret) != .SUCCESS) {
            std.debug.panic("waitpid failed\n", .{});
        }

        allocator.free(stack);
    }

    return 0;
}
