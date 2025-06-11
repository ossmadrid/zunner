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

const overlayfs = struct {
    lowerdir: [:0]const u8,
    upperdir: [:0]const u8,
    workdir: [:0]const u8,
    mergedDir: [:0]const u8,
    mountData: [:0]const u8,
    containerDir: [:0]const u8,

    pub fn init(allocator: std.mem.Allocator, containerId: []const u8) !*overlayfs {
        const ofsPtr = try allocator.create(overlayfs);
        const containerDir = try std.fs.path.joinZ(allocator, &.{ constants.ZUNNER_RUNTIME_DIR, containerId });
        const lowerdir = try std.fs.path.joinZ(allocator, &.{ constants.ZUNNER_RUNTIME_DIR, containerId, constants.LOWER_DIR });
        const upperdir = try std.fs.path.joinZ(allocator, &.{ constants.ZUNNER_RUNTIME_DIR, containerId, constants.UPPER_DIR });
        const workdir = try std.fs.path.joinZ(allocator, &.{ constants.ZUNNER_RUNTIME_DIR, containerId, constants.WORK_DIR });
        const mergedDir = try std.fs.path.joinZ(allocator, &.{ constants.ZUNNER_RUNTIME_DIR, containerId, constants.MERGED_DIR });
        const mountData = try std.fmt.allocPrintZ(allocator, "lowerdir={s},upperdir={s},workdir={s}", .{
            lowerdir, upperdir, workdir,
        });

        ofsPtr.* = overlayfs{
            .lowerdir = lowerdir,
            .upperdir = upperdir,
            .workdir = workdir,
            .mergedDir = mergedDir,
            .mountData = mountData,
            .containerDir = containerDir,
        };

        return ofsPtr;
    }

    pub fn createDirs(self: *overlayfs) !void {
        try std.fs.makeDirAbsolute(self.containerDir);
        try std.fs.makeDirAbsolute(self.lowerdir);
        try std.fs.makeDirAbsolute(self.upperdir);
        try std.fs.makeDirAbsolute(self.workdir);
        try std.fs.makeDirAbsolute(self.mergedDir);
    }

    pub fn deinit(self: *overlayfs, allocator: std.mem.Allocator) void {
        allocator.free(self.lowerdir);
        allocator.free(self.upperdir);
        allocator.free(self.workdir);
        allocator.free(self.mergedDir);
        allocator.free(self.mountData);
        allocator.free(self.containerDir);
        allocator.destroy(self);
    }
};

pub fn child(configPtr: usize) callconv(.C) u8 {
    const bin = "/bin/sh";
    const argv: [*:null]const ?[*:0]const u8 = &[_:null]?[*:0]const u8{ bin, "-i" };
    const envp: [*:null]const ?[*:0]const u8 = &[_:null]?[*:0]const u8{};
    const newRoot = "./alpine";
    const ofs: *overlayfs = @ptrFromInt(configPtr);

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
    ret = linux.mount(newRoot, ofs.lowerdir.ptr, null, linux.MS.BIND, 0);
    if (linux.E.init(ret) != .SUCCESS) {
        std.debug.panic("failed to bind mount new root: {}\n", .{linux.E.init(ret)});
    }

    //
    // Create a new OverlayFS mount on the merged directory
    //
    const mergedNewRoot = ofs.mergedDir;
    ret = linux.mount("overlay", mergedNewRoot.ptr, "overlay", 0, @intFromPtr(ofs.mountData.ptr));
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
    // Mount other filesystems (proc, sysfs, devtmpfs, etc.)
    //
    const mountFlags = linux.MS.NOEXEC | linux.MS.NOSUID | linux.MS.NODEV;

    ret = linux.mount("proc", "/proc", "proc", mountFlags, 0);
    if (linux.E.init(ret) != .SUCCESS) {
        std.debug.panic("mount proc failed: {}\n", .{linux.E.init(ret)});
    }

    ret = linux.mount("sysfs", "/sys", "sysfs", mountFlags | linux.MS.RDONLY, 0);
    if (linux.E.init(ret) != .SUCCESS) {
        std.debug.panic("mount sysfs failed: {}\n", .{linux.E.init(ret)});
    }

    ret = linux.mount("devtmpfs", "/dev", "devtmpfs", mountFlags, 0);
    if (linux.E.init(ret) != .SUCCESS) {
        std.debug.panic("mount devtmpfs failed: {}\n", .{linux.E.init(ret)});
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
    const ofs = try overlayfs.init(allocator, &containerId);
    defer ofs.deinit(allocator);

    try ofs.createDirs();

    std.log.info("Container ID: {s}", .{containerId});
    std.log.info("OverlayFS mount data: {s}", .{ofs.mountData});

    //
    // Clone child process
    //
    var ptid: i32 = 0;
    var ctid: i32 = 0;
    const stack = try allocator.alloc(u8, 1024 * 1024);
    defer allocator.free(stack);
    const nsFlags = linux.CLONE.NEWPID | linux.CLONE.NEWNS | linux.CLONE.NEWUTS;
    const pid = syscalls.clone(&child, @intFromPtr(&stack), constants.SIGCHLD | linux.CLONE.VFORK | nsFlags, @intFromPtr(ofs), &ptid, 0, &ctid) catch |err| {
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
