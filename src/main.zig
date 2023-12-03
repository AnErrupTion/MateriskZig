const std = @import("std");
const Parser = @import("Parser.zig");
const Binder = @import("Binder.zig");
const emitter = @import("emitter.zig");

pub fn main() !void {
    var arena = std.heap.ArenaAllocator.init(std.heap.page_allocator);
    defer arena.deinit();

    const allocator = arena.allocator();
    const code = @embedFile("main.msk");
    const stdout = std.io.getStdOut().writer();

    _ = try stdout.write("Parsing...\n");
    const nodes = try Parser.parse(allocator, code);

    var c_code = std.ArrayList(u8).init(allocator);

    const writer = c_code.writer();
    _ = try writer.write("int main() {\n    MateriskFunction_main();\n    return 0;\n}\n\n");

    _ = try stdout.write("Binding types...\n");
    const binder = try Binder.init(allocator, nodes.items);

    _ = try stdout.write("Emitting code...\n");
    for (nodes.items) |node| try emitter.codegen(0, writer, binder, node);

    _ = try stdout.write(c_code.items);
}
