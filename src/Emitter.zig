const Emitter = @This();

const Parser = @import("Parser.zig");
const Binder = @import("Binder.zig");

binder: Binder,
padding: usize,

pub fn init(binder: Binder) Emitter {
    return .{
        .binder = binder,
        .padding = 0,
    };
}

pub fn emit(self: *Emitter, writer: anytype, nodes: []Parser.Node) !void {
    for (nodes) |node| try self.codegen(writer, node);

    _ = try writer.write("int main() {\n    MateriskFunction_main();\n    return 0;\n}\n\n");
}

fn codegen(self: *Emitter, writer: anytype, node: Parser.Node) !void {
    switch (node) {
        .hexadecimal_literal => |hex| try writer.print("{s}", .{hex}),
        .decimal_literal => |dec| try writer.print("{s}", .{dec}),
        .identifier => |idn| _ = try writer.write(idn),
        .variable => |vrb| {
            if (self.padding > 0) try writer.writeByteNTimes(' ', self.padding);

            if (!vrb.mutable) _ = try writer.write("const ");
            _ = try writer.write(try self.binder.getTypeName(vrb.type));
            try writer.writeByte(' ');
            _ = try writer.write(vrb.name);
            _ = try writer.write(" = ");

            try self.codegen(writer, vrb.value.*);

            _ = try writer.write(";\n");
        },
        .assignment => |agn| {
            if (self.padding > 0) try writer.writeByteNTimes(' ', self.padding);

            if (agn.dereference) try writer.writeByte('*');
            _ = try writer.write(agn.name);
            _ = try writer.write(" = ");

            try self.codegen(writer, agn.value.*);

            _ = try writer.write(";\n");
        },
        .add => |add| {
            try self.codegen(writer, add.lhs.*);
            _ = try writer.write(" + ");
            try self.codegen(writer, add.rhs.*);
        },
        .subtract => |sub| {
            try self.codegen(writer, sub.lhs.*);
            _ = try writer.write(" - ");
            try self.codegen(writer, sub.rhs.*);
        },
        .multiply => |mul| {
            try self.codegen(writer, mul.lhs.*);
            _ = try writer.write(" * ");
            try self.codegen(writer, mul.rhs.*);
        },
        .divide => |div| {
            try self.codegen(writer, div.lhs.*);
            _ = try writer.write(" / ");
            try self.codegen(writer, div.rhs.*);
        },
        .modulus => |mod| {
            try self.codegen(writer, mod.lhs.*);
            _ = try writer.write(" % ");
            try self.codegen(writer, mod.rhs.*);
        },
        .negate => |neg| {
            try writer.writeByte('-');
            try self.codegen(writer, neg.*);
        },
        .call => unreachable,
        .function => |fun| {
            _ = try writer.write(try self.binder.getTypeName(fun.return_type));
            try writer.writeByte(' ');
            _ = try writer.write(try self.binder.getFunctionName(fun.name));
            _ = try writer.write("() {\n");

            self.padding += 4;
            for (fun.block) |child| try self.codegen(writer, child.*);
            self.padding -= 4;

            _ = try writer.write("}\n\n");
        },
        .structure => |stc| {
            const name = try self.binder.getTypeName(stc.name);
            _ = try writer.write("typedef struct __attribute__((__packed__)) ");
            _ = try writer.write(name);
            _ = try writer.write(" {\n");

            self.padding += 4;
            for (stc.fields) |field| try self.codegen(writer, field.*);
            self.padding -= 4;

            _ = try writer.write("} ");
            _ = try writer.write(name);
            _ = try writer.write(";\n\n");
        },
        .field => |fld| {
            if (self.padding > 0) try writer.writeByteNTimes(' ', self.padding);

            _ = try writer.write(try self.binder.getTypeName(fld.type));
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

                try self.codegen(writer, assignment.value.*);

                if (i != end) _ = try writer.write(", ");
            }

            _ = try writer.write(" }");
        },
        .cast => |cst| {
            try writer.writeByte('(');
            _ = try writer.write(try self.binder.getTypeName(cst.type));
            _ = try writer.write(") ");

            try self.codegen(writer, cst.value.*);
        },
        .compare => |cmp| {
            try self.codegen(writer, cmp.lhs.*);

            _ = try writer.write(switch (cmp.operator) {
                .equal => " == ",
                .not_equal => " != ",
                .below_equal => " <= ",
                .above_equal => " >= ",
                .below => " < ",
                .above => " > ",
            });

            try self.codegen(writer, cmp.rhs.*);
        },
        .if_condition => |ifc| {
            if (self.padding > 0) try writer.writeByteNTimes(' ', self.padding);

            _ = try writer.write("if (");

            try self.codegen(writer, ifc.condition.*);

            _ = try writer.write(") {\n");

            self.padding += 4;
            for (ifc.then_block) |child| try self.codegen(writer, child.*);
            self.padding -= 4;

            if (self.padding > 0) try writer.writeByteNTimes(' ', self.padding);
            try writer.writeByte('}');

            if (ifc.else_block) |else_block| {
                _ = try writer.write(" else {\n");

                self.padding += 4;
                for (else_block) |child| try self.codegen(writer, child.*);
                self.padding -= 4;

                if (self.padding > 0) try writer.writeByteNTimes(' ', self.padding);
                try writer.writeByte('}');
            }

            try writer.writeByte('\n');
        },
    }
}