const Binder = @This();

const std = @import("std");
const Parser = @import("Parser.zig");
const Allocator = std.mem.Allocator;

const TypeMap = std.StringArrayHashMap([]const u8);

allocator: Allocator,
names: TypeMap,

pub fn init(allocator: Allocator, nodes: []Parser.Node) !Binder {
    var binder = Binder{
        .allocator = allocator,
        .names = TypeMap.init(allocator),
    };

    try binder.names.put("void", "void");
    try binder.names.put("i8", "signed char");
    try binder.names.put("i16", "signed short");
    try binder.names.put("i32", "signed int");
    try binder.names.put("i64", "signed long long");
    try binder.names.put("u8", "unsigned char");
    try binder.names.put("u16", "unsigned short");
    try binder.names.put("u32", "unsigned int");
    try binder.names.put("u64", "unsigned long long");

    for (nodes) |node| try binder.bind(node);

    return binder;
}

pub fn getTypeName(self: Binder, name: []const u8) ![]const u8 {
    if (name[0] == '*') {
        const child_type = try self.getTypeName(name[1..]);
        return try std.fmt.allocPrint(self.allocator, "{s}*", .{child_type});
    }

    return self.names.get(name) orelse error.InvalidTypeName;
}

pub fn getFunctionName(self: Binder, name: []const u8) ![]const u8 {
    return self.names.get(name) orelse error.InvalidFunctionName;
}

fn bind(self: *Binder, node: Parser.Node) !void {
    switch (node) {
        .function => |fun| {
            const new_name = try std.fmt.allocPrint(self.allocator, "MateriskFunction_{s}", .{fun.name});
            try self.names.put(fun.name, new_name);
        },
        .structure => |stc| {
            const new_name = try std.fmt.allocPrint(self.allocator, "MateriskType_{s}", .{stc.name});
            try self.names.put(stc.name, new_name);
        },
        else => {},
    }
}