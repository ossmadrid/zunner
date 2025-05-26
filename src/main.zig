//! By convention, main.zig is where your main function lives in the case that
//! you are building an executable. If you are making a library, the convention
//! is to delete this file and start with root.zig instead.

const std = @import("std");
const linux = std.os.linux;
const os = std.os;
const cli = @import("cli.zig");

const SIGCHLD = 17;
const ZUNNER_RUNTIME_DIR = "/var/run/zunner";
const CONTAINER_ID_SIZE_BYTES = 32;
const CONTAINER_ID_SIZE_CHARS = CONTAINER_ID_SIZE_BYTES * 2;

pub fn generateContainerId(buf: []u8) !void {
    const file = try std.fs.openFileAbsolute("/dev/urandom", .{ .mode = .read_only });
    defer file.close();
    var bytes: [CONTAINER_ID_SIZE_BYTES]u8 = undefined;
    _ = try file.read(&bytes);
    const fmt = std.fmt.fmtSliceHexLower(&bytes);
    _ = try std.fmt.bufPrint(buf, "{}", .{fmt});
}

pub fn child(_: usize) callconv(.C) u8 {
    const bin = "/bin/sh";
    const argv: [*:null]const ?[*:0]const u8 = &[_:null]?[*:0]const u8{ bin, "-i" };
    const envp: [*:null]const ?[*:0]const u8 = &[_:null]?[*:0]const u8{};
    const newRoot = "./alpine";

    //
    // Remount root privately to ensure mount events are not replicated
    // in our view of the filesystem
    //
    var ret = linux.mount("", "/", null, linux.MS.PRIVATE | linux.MS.REC, 0);
    if (linux.E.init(ret) != .SUCCESS) {
        std.debug.panic("mount failed: {}\n", .{linux.E.init(ret)});
    }

    ret = linux.chroot(newRoot);
    if (linux.E.init(ret) != .SUCCESS) {
        std.debug.panic("chroot failed: {}\n", .{linux.E.init(ret)});
    }
    ret = linux.chdir("/");
    if (linux.E.init(ret) != .SUCCESS) {
        std.debug.panic("chdir failed: {}\n", .{linux.E.init(ret)});
    }

    //
    // Mount proc filesystem
    //
    ret = linux.mount("proc", "/proc", "proc", 0, 0);
    if (linux.E.init(ret) != .SUCCESS) {
        std.debug.panic("mount proc failed: {}\n", .{linux.E.init(ret)});
    }

    const hostname: []const u8 = "container";
    ret = linux.syscall2(.sethostname, @intFromPtr(hostname.ptr), hostname.len);
    if (linux.E.init(ret) != .SUCCESS) {
        std.debug.panic("mount proc failed: {}\n", .{linux.E.init(ret)});
    }

    _ = linux.execve(bin, argv, envp);
    std.debug.print("panic", .{});
    return 0;
}

pub fn main() !u8 {
    var gpa = std.heap.GeneralPurposeAllocator(.{}){};
    defer std.debug.assert(gpa.deinit() == .ok);
    const allocator = gpa.allocator();

    var args = cli.parseArgs(allocator) catch {
        std.debug.panic("Invalid args or an error occurred", .{});
    };
    defer args.deinit();

    if (cli.get_bool(args, "--help")) {
        cli.print_usage(args);
        return 0;
    }

    var buf: [CONTAINER_ID_SIZE_CHARS]u8 = undefined;
    try generateContainerId(&buf);
    std.debug.print("Hex: {s}\n", .{buf});

    var ptid: i32 = 0;
    var ctid: i32 = 0;
    const stack = try allocator.alloc(u8, 1024);
    defer allocator.free(stack);
    const pid = linux.clone(&child, @intFromPtr(&stack), SIGCHLD | linux.CLONE.NEWPID | linux.CLONE.NEWNS | linux.CLONE.NEWUTS, 0, &ptid, 0, &ctid);
    if (linux.E.init(pid) != .SUCCESS) {
        std.debug.panic("panic\n", .{});
    }

    if (pid != 0) { // parent
        std.time.sleep(100);
        const ret = linux.waitpid(-1, undefined, 0);
        if (linux.E.init(ret) != .SUCCESS) {
            std.debug.panic("waitpid failed\n", .{});
        }
    }

    return 0;
}
