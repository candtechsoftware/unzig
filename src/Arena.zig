const std = @import("std");
const os = @import("os.zig");
const windows = std.os.windows;

const Arena = @This();

const PAGE_SIZE = 4096;
const ARENA_HEADER_SIZE = 128;

const ArenaParams = struct {
    reserve_size: u64,
    commit_size: u64,
    allocation_site_file: []const u8,
    allocation_site_line: i32,
};

prev: ?*Arena = null,
current: ?*Arena = null,
cmt_size: u64,
res_size: u64,
base_pos: u64,
pos: u64,
cmt: u64,
res: u64,
allocation_site_file: []const u8,
allocation_site_line: i32,
free_size: u64 = 0,
free_last: ?*Arena = null,

pub fn alloc(params: ArenaParams) !*Arena {
    const page_size = PAGE_SIZE;
    const reserve_size = std.mem.alignForward(u64, params.reserve_size, page_size);
    const commit_size = std.mem.alignForward(u64, params.commit_size, page_size);

    const base = os.reserve(reserve_size) orelse return error.MemReserveFailed; 
    if (!os.commit(base, commit_size)) return error.MemCommitFailed; 

    const arena: *Arena = @ptrCast(@alignCast(base));
    arena.* = Arena{
        .prev = null,
        .current = arena,
        .cmt_size = commit_size,
        .res_size = reserve_size,
        .base_pos = 0,
        .pos = ARENA_HEADER_SIZE,
        .cmt = commit_size,
        .res = reserve_size,
        .allocation_site_file = params.allocation_site_file,
        .allocation_site_line = params.allocation_site_line,
    };
    return arena;
}

pub fn release(arena: *Arena) void {
    // Release all active arenas except the base arena
    var curr = arena.current;
    while (curr) |n| {
        const prev = n.prev;
        if (n != arena) {
            _ = windows.kernel32.VirtualFree(n, 0, windows.MEM_RELEASE);
        }
        curr = prev;
    }
    
    // Release all arenas in the free list
    curr = arena.free_last;
    while (curr) |n| {
        const prev = n.prev;
        _ = windows.kernel32.VirtualFree(n, 0, windows.MEM_RELEASE);
        curr = prev;
    }
    
    // Finally release the base arena itself
    _ = windows.kernel32.VirtualFree(arena, 0, windows.MEM_RELEASE);
}

pub fn push(arena: *Arena, size: u64, alignAt: u64) ?*u8 {
    var current = arena.current orelse arena;
    
    const pos_pre = std.mem.alignForward(u64, current.pos, alignAt);
    const pos_pst = pos_pre + size;

    if (current.res >= pos_pst) {
        if (current.cmt < pos_pst) {
            const cmt_pst_aligned = std.mem.alignForward(u64, pos_pst, current.cmt_size);
            const cmt_pst_clamped = @min(cmt_pst_aligned, current.res);
            const cmt_size = cmt_pst_clamped - current.cmt;
            const cmt_ptr: *u8 = @ptrFromInt(@intFromPtr(current) + current.cmt);
            _ = windows.kernel32.VirtualAlloc(cmt_ptr, cmt_size, windows.MEM_COMMIT, windows.PAGE_READWRITE);
            current.cmt = cmt_pst_clamped;
        }
        if (current.cmt >= pos_pst) {
            const result: *u8 = @ptrFromInt(@intFromPtr(current) + pos_pre);
            current.pos = pos_pst;
            return result;
        }
    }
    
    // Current arena is full, check free list first
    var new_arena: ?*Arena = null;
    
    // Check if we have a suitable arena in the free list
    if (arena.free_last) |free| {
        if (free.res_size >= size) {
            // Remove from free list
            new_arena = free;
            arena.free_last = free.prev;
            if (arena.free_last) |fl| {
                fl.current = null;
            }
            arena.free_size -|= free.res_size;
            
            // Reset the arena
            new_arena.?.pos = ARENA_HEADER_SIZE;
            new_arena.?.prev = current;
            new_arena.?.current = null;
        }
    }
    
    // If no suitable free arena, allocate a new one
    if (new_arena == null) {
        new_arena = alloc(.{
            .reserve_size = current.res_size,
            .commit_size = current.cmt_size,
            .allocation_site_file = current.allocation_site_file,
            .allocation_site_line = current.allocation_site_line,
        }) catch return null;
        
        new_arena.?.prev = current;
    }
    
    new_arena.?.base_pos = current.base_pos + current.res;
    arena.current = new_arena;
    
    // Try again with the new arena
    return arena.push(size, alignAt);
}

pub fn clear(arena: *Arena) void {
    // Move all chained arenas except the first one to free list
    if (arena.current != null and arena.current != arena) {
        var curr = arena.current;
        while (curr != null and curr != arena) {
            const prev = curr.?.prev;
            
            // Add to free list
            curr.?.prev = arena.free_last;
            curr.?.current = arena.free_last;
            arena.free_last = curr;
            arena.free_size += curr.?.res_size;
            
            curr = prev;
        }
    }
    
    // Reset to just the original arena
    arena.current = arena;
    arena.pos = ARENA_HEADER_SIZE;
}

pub fn popTo(arena: *Arena, pos: u64) void {
    // Find which arena contains this position
    var curr = arena.current orelse arena;
    
    // Move any arenas that are completely after this position to free list
    while (curr != arena and curr.base_pos >= pos) {
        const prev = curr.prev;
        if (prev) |p| {
            // Add to free list instead of releasing
            curr.prev = arena.free_last;
            curr.current = arena.free_last;
            arena.free_last = curr;
            arena.free_size += curr.res_size;
            
            arena.current = p;
            curr = p;
        } else {
            break;
        }
    }
    
    // Now set the position within the current arena
    if (pos >= curr.base_pos and pos < curr.base_pos + curr.res) {
        curr.pos = @max(ARENA_HEADER_SIZE, pos - curr.base_pos);
    }
}

pub fn getPos(arena: *Arena) u64 {
    const current = arena.current orelse arena;
    return current.base_pos + current.pos;
}

pub fn pop(arena: *Arena, amt: u64) void {
    const current_pos = arena.getPos();
    const new_pos = if (amt < current_pos) current_pos - amt else ARENA_HEADER_SIZE;
    arena.popTo(new_pos);
}

pub const Scratch = struct {
    arena: *Arena,
    pos: u64,

    pub fn begin(arena: *Arena) Scratch {
        return Scratch{
            .arena = arena,
            .pos = arena.getPos(),
        };
    }

    pub fn end(self: Scratch) void {
        self.arena.popTo(self.pos);
    }
};

pub fn getStats(arena: *Arena) struct { active_count: u32, active_size: u64, free_count: u32, free_size: u64 } {
    var active_count: u32 = 0;
    var active_size: u64 = 0;
    var free_count: u32 = 0;
    
    // Count active arenas
    var curr = arena.current orelse arena;
    while (true) {
        active_count += 1;
        active_size += curr.res_size;
        if (curr.prev) |p| {
            if (p == arena) {
                active_count += 1;
                active_size += arena.res_size;
                break;
            }
            curr = p;
        } else {
            break;
        }
    }
    
    // Count free arenas
    var free_curr = arena.free_last;
    while (free_curr) |n| {
        free_count += 1;
        free_curr = n.prev;
    }
    
    return .{
        .active_count = active_count,
        .active_size = active_size,
        .free_count = free_count,
        .free_size = arena.free_size,
    };
}

fn allocFn(ctx: *anyopaque, len: usize, ptr_align: std.mem.Alignment, ret_addr: usize) ?[*]u8 {
    _ = ret_addr;
    const self: *Arena = @ptrCast(@alignCast(ctx));
    const alignment = @as(usize, 1) << @intCast(@intFromEnum(ptr_align));
    if (self.push(len, alignment)) |ptr| {
        return @ptrCast(ptr);
    }
    return null;
}

fn resizeFn(ctx: *anyopaque, buf: []u8, buf_align: std.mem.Alignment, new_len: usize, ret_addr: usize) bool {
    _ = ctx;
    _ = buf;
    _ = buf_align;
    _ = new_len;
    _ = ret_addr;
    // Arena allocators cannot resize allocations
    return false;
}

fn freeFn(ctx: *anyopaque, buf: []u8, buf_align: std.mem.Alignment, ret_addr: usize) void {
    _ = ctx;
    _ = buf;
    _ = buf_align;
    _ = ret_addr;
    // Arena allocators don't free individual allocations
}

fn remapFn(ctx: *anyopaque, old_buf: []u8, old_align: std.mem.Alignment, new_size: usize, ret_addr: usize) ?[*]u8 {
    _ = ctx;
    _ = old_buf;
    _ = old_align;
    _ = new_size;
    _ = ret_addr;
    // Arena allocators don't support remapping
    return null;
}

pub fn allocator(self: *Arena) std.mem.Allocator {
    return std.mem.Allocator{
        .ptr = self,
        .vtable = &std.mem.Allocator.VTable{
            .alloc = allocFn,
            .resize = resizeFn,
            .free = freeFn,
            .remap = remapFn,
        },
    };
}
