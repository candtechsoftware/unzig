const std = @import("std");
const windows = std.os.windows;

const PAGE_SIZE: usize = 4096;

const SystemInfo = struct {
    page_size: usize,
};

pub fn reserve(size: usize) ?*anyopaque {
    return windows.kernel32.VirtualAlloc(
        null,
        size,
        windows.MEM_RESERVE,
        windows.PAGE_NOACCESS,
    );
}

pub fn commit(ptr: *anyopaque, size: usize) bool {
    return windows.kernel32.VirtualAlloc(
        ptr,
        size,
        windows.MEM_COMMIT,
        windows.PAGE_READWRITE,
    ) != null;
}

pub fn decommit(ptr: *anyopaque, size: usize) void {
    _ = windows.kernel32.VirtualFree(ptr, size, windows.MEM_DECOMMIT);
}

pub fn release(ptr: *anyopaque, size: usize) void {
    _ = windows.kernel32.VirtualFree(ptr, size, windows.MEM_RELEASE);
}

pub fn os_get_sys_info() SystemInfo {
    var info: windows.SYSTEM_INFO = undefined;
    windows.kernel32.GetSystemInfo(&info);
    return .{
        .page_size = info.dwPageSize,
    };
}
