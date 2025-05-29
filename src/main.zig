//! By convention, main.zig is where your main function lives in the case that
//! you are building an executable. If you are making a library, the convention
//! is to delete this file and start with root.zig instead.

const std = @import("std");
const linux = std.os.linux;
const os = std.os;
const cli = @import("cli.zig");
const constants = @import("constants.zig");
const utils = @import("utils.zig");
const syscalls = @import("syscalls.zig");

var paths: [4][:0]u8 = undefined; // todo: this should not be global
var mountData: [:0]const u8 = undefined; // todo: this should not be global

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
        std.debug.panic("failed to remove shared propagation on mount: {}\n", .{linux.E.init(ret)});
    }

    //
    // Bind mount the new root filesystem to the lower layer of OverlayFS
    //
    ret = linux.mount(newRoot, paths[0], null, linux.MS.BIND, 0);
    if (linux.E.init(ret) != .SUCCESS) {
        std.debug.panic("failed to bind mount new root: {}\n", .{linux.E.init(ret)});
    }

    //
    // Create a new OverlayFS mount on the merged directory
    //
    const mergedNewRoot = paths[3];
    ret = linux.mount("overlay", mergedNewRoot, "overlay", 0, @intFromPtr(mountData.ptr));
    if (linux.E.init(ret) != .SUCCESS) {
        std.debug.panic("failed to mount overlayfs: {}\n", .{linux.E.init(ret)});
    }

    //
    // Prepare pivoting by placing old root under new root, so that we don't lose its reference
    //
    const oldRoot = "old";
    var realpathBuf: [4096]u8 = undefined;
    const fullNewRoot = std.fs.realpath(mergedNewRoot, &realpathBuf) catch |err| {
        std.debug.panic("realpath failed: {s}", .{@errorName(err)});
    };
    var pathBuf: [4096]u8 = undefined;
    const fullOldRoot = std.fmt.bufPrintZ(&pathBuf, "{s}/{s}", .{ fullNewRoot, oldRoot }) catch |err| {
        std.debug.panic("failed to join full old root path: {s}", .{@errorName(err)});
    };
    std.fs.makeDirAbsolute(fullOldRoot) catch |err| {
        std.debug.panic("mkdir failed: {s}", .{@errorName(err)});
    };

    //
    // Pivot root
    //
    ret = linux.syscall2(.pivot_root, @intFromPtr(mergedNewRoot.ptr), @intFromPtr(fullOldRoot.ptr));
    if (linux.E.init(ret) != .SUCCESS) {
        std.debug.panic("pivot failed: {}\n", .{linux.E.init(ret)});
    }

    ret = linux.umount2("/old", linux.MNT.DETACH);
    if (linux.E.init(ret) != .SUCCESS) {
        std.debug.panic("umount failed: {}\n", .{linux.E.init(ret)});
    }

    ret = linux.rmdir("/old");
    if (linux.E.init(ret) != .SUCCESS) {
        std.debug.panic("rmdir failed: {}\n", .{linux.E.init(ret)});
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

    //
    // Ensure the runtime directory exists
    //
    _ = std.fs.accessAbsolute(constants.ZUNNER_RUNTIME_DIR, .{ .mode = .read_write }) catch |err| {
        if (err == std.fs.Dir.AccessError.FileNotFound) {
            try std.fs.makeDirAbsolute(constants.ZUNNER_RUNTIME_DIR);
        } else {
            std.debug.panic("Failed to access runtime directory", .{});
        }
    };

    //
    // Generate container id
    //
    var containerId: [constants.CONTAINER_ID_SIZE_CHARS]u8 = undefined;
    utils.generateContainerId(&containerId) catch {
        std.debug.panic("error generating container id", .{});
    };

    //
    // Create runtime directory for the container, containing lower, upper, work and merged directories
    // used by OverlayFS
    //
    const containerRuntimeDir = std.fs.path.join(allocator, &.{ constants.ZUNNER_RUNTIME_DIR, &containerId }) catch |err| {
        std.debug.panic("Failed to join container runtime directory path, error: {s}", .{@errorName(err)});
    };
    defer allocator.free(containerRuntimeDir);
    std.fs.makeDirAbsolute(containerRuntimeDir) catch |err| {
        std.debug.panic("failed to create container runtime directory, id: {s}, error: {s}", .{ containerId, @errorName(err) });
    };

    const dirs = [4][]const u8{ constants.LOWER_DIR, constants.UPPER_DIR, constants.WORK_DIR, constants.MERGED_DIR };
    for (dirs, 0..) |dir, i| {
        const path = std.fs.path.joinZ(allocator, &.{ containerRuntimeDir, dir }) catch |err| {
            std.debug.panic("Failed to join container runtime directory path for {s} dir, error: {s}", .{ dir, @errorName(err) });
        };
        std.fs.makeDirAbsolute(path) catch |err| {
            std.debug.panic("failed to create {s} directory for id: {s}, error: {s}", .{ dir, containerId, @errorName(err) });
        };
        paths[i] = path;
    }
    mountData = std.fmt.allocPrintZ(allocator, "lowerdir={s},upperdir={s},workdir={s}", .{
        paths[0], paths[1], paths[2],
    }) catch |err| {
        std.debug.panic("Failed to format OverlayFS data, error: {s}", .{@errorName(err)});
    };
    defer {
        for (paths) |p| allocator.free(p);
        allocator.free(mountData);
    }
    std.log.info("Container ID: {s}", .{containerId});
    std.log.info("Container runtime directory: {s}", .{containerRuntimeDir});
    std.log.info("OverlayFS mount data: {s}", .{mountData});

    var ptid: i32 = 0;
    var ctid: i32 = 0;
    const stack = try allocator.alloc(u8, 1024 * 1024);
    defer allocator.free(stack);
    const nsFlags = linux.CLONE.NEWPID | linux.CLONE.NEWNS | linux.CLONE.NEWUTS;
    const pid = syscalls.clone(&child, @intFromPtr(&stack), constants.SIGCHLD | linux.CLONE.VFORK | nsFlags, 0, &ptid, 0, &ctid) catch |err| {
        const msg = switch (err) {
            syscalls.SyscallError.PERM => "Cannot spawn the child process. Did you forget to run with 'sudo'?\n",
            else => @errorName(err),
        };
        std.log.err("clone: {s}", .{msg});
        std.process.exit(1);
    };

    if (pid != 0) { // parent
        const status = try syscalls.waitpid(pid, 0);
        return status.exitStatus();
    }

    return 0;
}
