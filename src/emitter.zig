const Parser = @import("Parser.zig");
const Binder = @import("Binder.zig");

pub fn codegen(padding: usize, writer: anytype, binder: Binder, node: Parser.Node) !void {
    switch (node) {
        .hexadecimal_literal => |num| try writer.print("{s}", .{num}),
        .decimal_literal => |num| try writer.print("{s}", .{num}),
        .identifier => |idn| _ = try writer.write(idn),
        .variable => |vrb| {
            if (padding > 0) try writer.writeByteNTimes(' ', padding);

            if (!vrb.mutable) _ = try writer.write("const ");
            _ = try writer.write(try binder.getTypeName(vrb.type));
            try writer.writeByte(' ');
            _ = try writer.write(vrb.name);
            _ = try writer.write(" = ");
            try codegen(padding, writer, binder, vrb.value.*);
            _ = try writer.write(";\n");
        },
        .assignment => |agn| {
            if (padding > 0) try writer.writeByteNTimes(' ', padding);

            if (agn.dereference) try writer.writeByte('*');
            _ = try writer.write(agn.name);
            _ = try writer.write(" = ");
            try codegen(padding, writer, binder, agn.value.*);
            _ = try writer.write(";\n");
        },
        .add => |add| {
            try codegen(padding, writer, binder, add.lhs.*);
            _ = try writer.write(" + ");
            try codegen(padding, writer, binder, add.rhs.*);
        },
        .subtract => |sub| {
            try codegen(padding, writer, binder, sub.lhs.*);
            _ = try writer.write(" - ");
            try codegen(padding, writer, binder, sub.rhs.*);
        },
        .multiply => |mul| {
            try codegen(padding, writer, binder, mul.lhs.*);
            _ = try writer.write(" * ");
            try codegen(padding, writer, binder, mul.rhs.*);
        },
        .divide => |div| {
            try codegen(padding, writer, binder, div.lhs.*);
            _ = try writer.write(" / ");
            try codegen(padding, writer, binder, div.rhs.*);
        },
        .modulus => |mod| {
            try codegen(padding, writer, binder, mod.lhs.*);
            _ = try writer.write(" % ");
            try codegen(padding, writer, binder, mod.rhs.*);
        },
        .negate => |neg| {
            try writer.writeByte('-');
            try codegen(padding, writer, binder, neg.*);
        },
        .call => unreachable,
        .function => |fun| {
            _ = try writer.write(try binder.getTypeName(fun.return_type));
            try writer.writeByte(' ');
            _ = try writer.write(try binder.getFunctionName(fun.name));
            _ = try writer.write("() {\n");
            const new_padding = padding + 4;
            for (fun.block) |child| try codegen(new_padding, writer, binder, child.*);
            _ = try writer.write("}\n\n");
        },
        .structure => |stc| {
            const name = try binder.getTypeName(stc.name);
            _ = try writer.write("struct __attribute__((__packed__)) ");
            _ = try writer.write(name);
            _ = try writer.write(" {\n");
            const new_padding = padding + 4;
            for (stc.fields) |field| try codegen(new_padding, writer, binder, field.*);
            _ = try writer.write("} ");
            _ = try writer.write(name);
            _ = try writer.write(";\n\n");
        },
        .field => |fld| {
            if (padding > 0) try writer.writeByteNTimes(' ', padding);

            _ = try writer.write(try binder.getTypeName(fld.type));
            try writer.writeByte(' ');
            _ = try writer.write(fld.name);
            _ = try writer.write(";\n");
        },
        .struct_initialization => |sti| {
            _ = try writer.write("{ ");
            const end = sti.assignments.len - 1;
            for (sti.assignments, 0..) |child, i| {
                const assignment = child.assignment;
                try writer.writeByte('.');
                _ = try writer.write(assignment.name);
                _ = try writer.write(" = ");
                try codegen(padding, writer, binder, assignment.value.*);
                if (i != end) _ = try writer.write(", ");
            }
            _ = try writer.write(" }");
        },
        .cast => |cst| {
            try writer.writeByte('(');
            _ = try writer.write(try binder.getTypeName(cst.type));
            try writer.writeByte(')');
            try codegen(padding, writer, binder, cst.value.*);
        },
    }
}