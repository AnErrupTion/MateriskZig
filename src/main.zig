const std = @import("std");
const Parser = @import("Parser.zig");
const Binder = @import("Binder.zig");
const emitter = @import("emitter.zig");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    const allocator = arena.allocator();
    const directory = std.fs.cwd();

    std.log.info("Reading file...", .{});
    const input_file = try directory.openFile("main.msk", .{});
    defer input_file.close();

    const code = try input_file.readToEndAlloc(allocator, 128 * 1024);

    std.log.info("Parsing...", .{});
    const nodes = try Parser.parse(allocator, code);

    const output_file = try directory.createFile("main.c", .{});
    defer output_file.close();

    const writer = output_file.writer();

    std.log.info("Binding types...", .{});
    const binder = try Binder.init(allocator, nodes.items);

    std.log.info("Emitting code...", .{});
    try emitter.emit(writer, binder, nodes.items);
}
