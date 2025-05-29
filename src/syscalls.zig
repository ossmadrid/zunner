const std = @import("std");
const linux = std.os.linux;

// Convert an Enum into an error set.
// The names of the Enum fields will become values of the error set.
fn enumToErrors(Enum: type) type {
    const e_fields = @typeInfo(Enum).@"enum".fields;
    var errors: [e_fields.len]std.builtin.Type.Error = undefined;
    for (e_fields, 0..) |f, i| {
        errors[i] = .{
            .name = f.name,
        };
    }
    return @Type(.{ .error_set = &errors });
}

pub const SyscallError = enumToErrors(linux.E);

fn toSyscallError(e: linux.E) SyscallError {
    // create a comptime map linux.E -> SyscallError
    // assumption: enum names and SyscallErrors' names are equal
    const enum_info = @typeInfo(SyscallError).error_set orelse unreachable;
    const KeyPair = struct { []const u8, SyscallError };
    comptime var static_key_pairs: [enum_info.len]KeyPair = undefined;
    comptime for (enum_info, 0..) |f, i| {
        static_key_pairs[i] = .{ f.name, @field(SyscallError, f.name) };
    };
    const m = std.StaticStringMap(SyscallError).initComptime(static_key_pairs);

    const name = @tagName(e);
    return m.get(name) orelse unreachable;
}

pub const WaitpidResult = struct {
    pid: linux.pid_t,
    status: u32,

    pub fn exitStatus(self: @This()) u8 {
        return linux.W.EXITSTATUS(self.status);
    }
};

pub fn waitpid(pid: linux.pid_t, flags: u32) SyscallError!WaitpidResult {
    var result = WaitpidResult{
        .pid = undefined,
        .status = undefined,
    };
    const ret = linux.waitpid(pid, &result.status, flags);
    const err = linux.E.init(ret);
    if (err != .SUCCESS) {
        return toSyscallError(err);
    }
    return result;
}

pub fn clone(
    func: *const fn (arg: usize) callconv(.c) u8,
    stack: usize,
    flags: u32,
    arg: usize,
    ptid: ?*i32,
    tp: usize, // aka tls
    ctid: ?*i32,
) SyscallError!linux.pid_t {
    const ret = linux.clone(func, stack, flags, arg, ptid, tp, ctid);
    const err = linux.E.init(ret);
    if (err != .SUCCESS) {
        return toSyscallError(err);
    }
    const signed_ret: isize = @bitCast(ret);
    return @truncate(signed_ret);
}
