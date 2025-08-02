const std = @import("std");
const unzig = @import("root.zig");

const log = std.log.scoped(.extractor);

pub const ExtractionOptions = struct {
    batch_size: usize = 16,
    create_directories: bool = true,
    validate_pe_headers: bool = true,
    show_progress: bool = true,
};

pub const ExtractionStats = struct {
    files_extracted: u64 = 0,
    directories_created: u64 = 0,
    bytes_written: u64 = 0,
    extraction_time_ms: u64 = 0,
};

pub fn extractZipToDirectory(
    zip_reader: *unzig.ZipReader,
    dest_dir_path: []const u8,
    arena: *unzig.Arena,
    options: ExtractionOptions,
) !ExtractionStats {
    const start_time = std.time.milliTimestamp();
    var stats = ExtractionStats{};
    
    
    // Create destination directory
    std.fs.cwd().makePath(dest_dir_path) catch |err| {
        if (err != error.PathAlreadyExists) return err;
    };
    
    var dest = try std.fs.cwd().openDir(dest_dir_path, .{});
    defer dest.close();
    
    // Sort entries by directory depth for efficient extraction
    std.mem.sort(unzig.ZipEntry, zip_reader.entries.items, {}, compareByDepth);
    
    // Separate directories from files
    var directories = std.ArrayList([]const u8).init(arena.allocator());
    var files = std.ArrayList(*unzig.ZipEntry).init(arena.allocator());
    
    for (zip_reader.entries.items) |*entry| {
        if (entry.file_name.len > 0 and entry.file_name[entry.file_name.len - 1] == '/') {
            const dir_name = entry.file_name[0..entry.file_name.len - 1];
            try directories.append(dir_name);
        } else {
            try files.append(entry);
        }
    }
    
    // Create directories first
    if (options.create_directories) {
        for (directories.items) |dir_name| {
            log.debug("Creating directory {s}", .{dir_name});
            dest.makePath(dir_name) catch |err| {
                if (err != error.PathAlreadyExists) {
                    log.err("Failed to create directory {s}: {}", .{ dir_name, err });
                    return err;
                }
            };
            stats.directories_created += 1;
        }
    }
    
    // Extract files in batches
    var batch_start: usize = 0;
    while (batch_start < files.items.len) {
        const batch_end = @min(batch_start + options.batch_size, files.items.len);
        const batch_files = files.items[batch_start..batch_end];
        
        for (batch_files) |entry| {
            try extractSingleFile(entry, zip_reader, dest, arena, options);
            stats.files_extracted += 1;
            stats.bytes_written += entry.uncompressed_size;
        }
        
        
        batch_start = batch_end;
    }
    
    stats.extraction_time_ms = @intCast(std.time.milliTimestamp() - start_time);
    
    return stats;
}

fn extractSingleFile(
    entry: *unzig.ZipEntry,
    zip_reader: *unzig.ZipReader,
    dest: std.fs.Dir,
    arena: *unzig.Arena,
    options: ExtractionOptions,
) !void {
    if (options.show_progress) {
        log.debug("Extracting {s}... ({d} bytes)", .{ entry.file_name, entry.uncompressed_size });
    }
    
    const scratch = unzig.Arena.Scratch.begin(arena);
    defer scratch.end();
    
    if (std.fs.path.dirname(entry.file_name)) |dir| {
        dest.makePath(dir) catch |err| {
            if (err != error.PathAlreadyExists) return err;
        };
    }
    
    const data = zip_reader.extractFile(entry, arena) catch |err| {
        log.err("Failed to extract {s}: {}", .{ entry.file_name, err });
        return err;
    };
    
    if (data.len != entry.uncompressed_size) {
        log.warn("Size mismatch in {s}: expected {d}, got {d}", .{ entry.file_name, entry.uncompressed_size, data.len });
    }
    
    if (options.validate_pe_headers and std.mem.endsWith(u8, entry.file_name, ".exe") and data.len >= 64) {
        if (data[0] != 'M' or data[1] != 'Z') {
            log.warn("Invalid PE header in {s}: 0x{X:0>2} 0x{X:0>2}", .{ entry.file_name, data[0], data[1] });
        } else {
            log.debug("PE header OK for {s}", .{entry.file_name});
        }
    }
    const out_file = try dest.createFile(entry.file_name, .{});
    defer out_file.close();
    try out_file.writeAll(data);
}

fn compareByDepth(context: void, a: unzig.ZipEntry, b: unzig.ZipEntry) bool {
    _ = context;
    
    const depth_a = std.mem.count(u8, a.file_name, "/");
    const depth_b = std.mem.count(u8, b.file_name, "/");
    
    const is_dir_a = a.file_name.len > 0 and a.file_name[a.file_name.len - 1] == '/';
    const is_dir_b = b.file_name.len > 0 and b.file_name[b.file_name.len - 1] == '/';
    
    if (depth_a != depth_b) {
        return depth_a < depth_b;
    }
    
    if (is_dir_a != is_dir_b) {
        return is_dir_a;
    }
    
    return unzig.simdStringCompare(a.file_name, b.file_name) == .lt;
}