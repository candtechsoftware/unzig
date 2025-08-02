const std = @import("std");
const unzig = @import("unzig");

const log = std.log.scoped(.main);

pub const std_options: std.Options = .{
    .log_level = .info,
    .logFn = customLogFn,
};

pub fn customLogFn(
    comptime level: std.log.Level,
    comptime scope: @Type(.enum_literal),
    comptime format: []const u8,
    args: anytype,
) void {
    const scope_prefix = switch (scope) {
        .main, .extractor, .deflate, std.log.default_log_scope => @tagName(scope),
        else => if (@intFromEnum(level) <= @intFromEnum(std.log.Level.err))
            @tagName(scope)
        else
            return,
    };

    const prefix = "[" ++ comptime level.asText() ++ "] (" ++ scope_prefix ++ "): ";
    std.debug.print(prefix ++ format ++ "\n", args);
}

pub fn main() !void {
    var arena = try unzig.Arena.alloc(.{
        .reserve_size = 2 * 1024 * 1024 * 1024, // 2GB reserved address space
        .commit_size = 64 * 1024 * 1024,        // 64MB initial commit
        .allocation_site_file = @src().file,
        .allocation_site_line = @src().line,
    });
    defer arena.release();
    
    const temp_allocator = std.heap.page_allocator;
    const args = try std.process.argsAlloc(temp_allocator);
    defer std.process.argsFree(temp_allocator, args);

    if (args.len < 2) {
        log.err("Usage: {s} <zipfile> [destination_directory]", .{args[0]});
        log.err("  If destination_directory is provided, files will be extracted there", .{});
        return error.InvalidArgs;
    }

    const zip_file_path = args[1];
    const file = try std.fs.cwd().openFile(zip_file_path, .{});
    defer file.close();
    
    const file_data = file.readToEndAlloc(arena.allocator(), std.math.maxInt(usize)) catch |err| {
        log.err("Failed to read file: {}", .{err});
        return err;
    };
    
    var zip_reader = unzig.ZipReader.init(arena, file_data) catch |err| {
        log.err("Failed to parse ZIP: {}", .{err});
        return err;
    };
    defer zip_reader.deinit();

    if (args.len >= 3) {
        const dest_dir = args[2];
        
        const extraction_options = unzig.extractor.ExtractionOptions{
            .batch_size = 16,
            .create_directories = true,
            .validate_pe_headers = true,
            .show_progress = false,
        };
        
        _ = try unzig.extractor.extractZipToDirectory(
            &zip_reader, 
            dest_dir, 
            arena, 
            extraction_options
        );
    }
    
}
